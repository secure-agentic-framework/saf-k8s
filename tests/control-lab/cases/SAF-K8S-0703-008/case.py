"""Live Prometheus policy evaluation with synthetic telemetry and bounded scale-down.

This case creates no GPU device request and consumes no GPU hardware. The only
reclamation target is the case-owned synthetic Deployment in the lab namespace.
"""
import json
import time

from fixtures import BUSYBOX_IMAGE


PROMETHEUS_IMAGE = "docker.io/prom/prometheus:v3.16.0@sha256:e04987641b57704f408e31f6373ba4138ecf27cb4a165d24aabb6c38fddd0f06"
PYTHON_IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
NAMESPACE = "saf-test"
CASE_ID = "SAF-K8S-0703-008"
TELEMETRY_NAME = "saf-0703-008-telemetry"
PROMETHEUS_NAME = "saf-0703-008-prometheus"
TARGET_NAME = "saf-0703-008-idle-target"
PROTECTED_NAME = "saf-0703-008-active-protected"
ALERT_NAME = "SyntheticGpuIdle"
METRIC = "saf_synthetic_gpu_utilization_percent"

SCOPE = (
    "Prometheus v3.16.0 evaluates synthetic telemetry: a utilization gauge served by a local "
    "test endpoint. An 80-to-0 synthetic metric transition exercises a 10-second "
    "low-utilization alert. The lab runner scales exactly the case-owned "
    "saf-0703-008-idle-target Deployment from one replica to zero only after it "
    "observes a firing alert with the expected case_id and synthetic gpu_id labels. "
    "A separate synthetic protected Deployment must remain ready. No DCGM exporter, "
    "NVIDIA driver, GPU resource request, device plugin, hardware utilization, real "
    "GPU allocation, production workload, or production reclamation is involved."
)

TELEMETRY_SERVER = r'''from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_error(404)
            return
        body = Path("/data/metrics.prom").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
HTTPServer(("0.0.0.0", 9400), Handler).serve_forever()
'''

PROMETHEUS_CONFIG = """global:
  scrape_interval: 2s
  evaluation_interval: 2s
rule_files:
  - /etc/prometheus/idle.yaml
scrape_configs:
  - job_name: synthetic-gpu-telemetry
    static_configs:
      - targets: [saf-0703-008-telemetry:9400]
"""

IDLE_RULE = """groups:
- name: saf-0703-008-synthetic
  rules:
  - alert: SyntheticGpuIdle
    expr: saf_synthetic_gpu_utilization_percent{case_id="SAF-K8S-0703-008",gpu_id="synthetic-0"} <= 5
    for: 10s
    labels:
      severity: test
    annotations:
      summary: Synthetic low-utilization policy probe
"""


def labels(extra=None):
    return {"saf.example/control": CASE_ID, **(extra or {})}


def metrics(value):
    return (
        "# HELP saf_synthetic_gpu_utilization_percent Synthetic test input; not GPU telemetry.\n"
        "# TYPE saf_synthetic_gpu_utilization_percent gauge\n"
        f'saf_synthetic_gpu_utilization_percent{{case_id="{CASE_ID}",gpu_id="synthetic-0"}} {value}\n'
    )


def resources(utilization):
    telemetry = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": TELEMETRY_NAME, "namespace": NAMESPACE,
                     "labels": labels()},
        "data": {"metrics.prom": metrics(utilization)},
    }
    rules = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": f"{PROMETHEUS_NAME}-config", "namespace": NAMESPACE,
                     "labels": labels()},
        "data": {"prometheus.yml": PROMETHEUS_CONFIG, "idle.yaml": IDLE_RULE},
    }
    telemetry_deploy = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": TELEMETRY_NAME, "namespace": NAMESPACE,
                     "labels": labels()},
        "spec": {"replicas": 1,
                 "selector": {"matchLabels": {"app": TELEMETRY_NAME}},
                 "template": {"metadata": {"labels": {"app": TELEMETRY_NAME, **labels()}},
                              "spec": {"automountServiceAccountToken": False, "containers": [{
                                  "name": "synthetic-metrics", "image": PYTHON_IMAGE,
                                  "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                      "allowPrivilegeEscalation": False},
                                  "command": ["python", "-u", "-c", TELEMETRY_SERVER],
                                  "ports": [{"name": "metrics", "containerPort": 9400}],
                                  "volumeMounts": [{"name": "metrics", "mountPath": "/data",
                                                    "readOnly": True}],
                              }], "volumes": [{"name": "metrics",
                                               "configMap": {"name": TELEMETRY_NAME}}]}}},
    }
    telemetry_service = {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": TELEMETRY_NAME, "namespace": NAMESPACE,
                     "labels": labels()},
        "spec": {"selector": {"app": TELEMETRY_NAME},
                 "ports": [{"name": "metrics", "port": 9400, "targetPort": 9400}]},
    }
    prometheus = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": PROMETHEUS_NAME, "namespace": NAMESPACE,
                     "labels": labels()},
        "spec": {"replicas": 1,
                 "selector": {"matchLabels": {"app": PROMETHEUS_NAME}},
                 "template": {"metadata": {"labels": {"app": PROMETHEUS_NAME, **labels()}},
                              "spec": {"automountServiceAccountToken": False, "containers": [{
                                  "name": "prometheus", "image": PROMETHEUS_IMAGE,
                                  "args": ["--config.file=/etc/prometheus/prometheus.yml",
                                           "--storage.tsdb.path=/prometheus",
                                           "--web.listen-address=0.0.0.0:9090",
                                           "--storage.tsdb.retention.time=1h"],
                                  "ports": [{"name": "web", "containerPort": 9090}],
                                  "volumeMounts": [{"name": "config", "mountPath": "/etc/prometheus",
                                                    "readOnly": True}],
                              }], "volumes": [{"name": "config", "configMap": {
                                  "name": f"{PROMETHEUS_NAME}-config"}}]}}},
    }
    prometheus_service = {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": PROMETHEUS_NAME, "namespace": NAMESPACE,
                     "labels": labels()},
        "spec": {"selector": {"app": PROMETHEUS_NAME},
                 "ports": [{"name": "web", "port": 9090, "targetPort": 9090}]},
    }
    target = synthetic_workload(TARGET_NAME)
    protected = synthetic_workload(PROTECTED_NAME)
    return [telemetry, rules, telemetry_deploy, telemetry_service, prometheus,
            prometheus_service, target, protected]


def synthetic_workload(name):
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": labels({"saf.example/role": "synthetic-workload"})},
        "spec": {"replicas": 1,
                 "selector": {"matchLabels": {"app": name}},
                 "template": {"metadata": {"labels": {"app": name, **labels()}},
                              "spec": {"automountServiceAccountToken": False, "containers": [{
                                  "name": "sleep", "image": BUSYBOX_IMAGE,
                                  "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                      "allowPrivilegeEscalation": False},
                                  "command": ["sh", "-c", "sleep 3600"],
                              }]}}},
    }


def wait_ready(lab, name, timeout=120):
    lab.kubectl("wait", "--for=condition=Available", f"deployment/{name}",
                "--timeout=120s", timeout=125)


def deployment(lab, name):
    return json.loads(lab.kubectl("get", "deployment", name, "-o", "json").stdout)


def wait_for_target_pods_gone(lab, timeout=60):
    deadline = time.monotonic() + timeout
    latest = []
    while time.monotonic() < deadline:
        pods = json.loads(lab.kubectl(
            "get", "pods", "-l", f"app={TARGET_NAME}", "-o", "json").stdout)
        latest = pods.get("items", [])
        if not latest:
            return
        time.sleep(1)
    lab.block(f"Synthetic target Pods were not removed after scale-down: {latest}")



def prom_data(lab, suffix):
    url = f"http://{PROMETHEUS_NAME}:9090{suffix}"
    script = "from urllib.request import urlopen; import sys; print(urlopen(sys.argv[1], timeout=4).read().decode())"
    reply = lab.kubectl("exec", f"deployment/{TELEMETRY_NAME}", "--", "python", "-c", script, url,
                        timeout=18, allow_failure=True)
    if reply.returncode:
        return None
    data = json.loads(reply.stdout)
    return data["data"] if data.get("status") == "success" else None


def wait_for_metric(lab, expected):
    end = time.monotonic() + 45
    while True:
        reading = prom_data(lab, f"/api/v1/query?query={METRIC}")
        results = reading.get("result", []) if reading else []
        values = [float(item["value"][1]) for item in results
                  if item["metric"].get("case_id") == CASE_ID
                  and item["metric"].get("gpu_id") == "synthetic-0"]
        if values == [float(expected)]:
            return
        if time.monotonic() >= end:
            lab.block(f"Prometheus did not scrape the expected synthetic value {expected}")
        time.sleep(0.5)


def current_alert(lab):
    payload = prom_data(lab, "/api/v1/alerts")
    for alert in payload.get("alerts", []) if payload else []:
        tags = alert.get("labels", {})
        if tags.get("alertname") == ALERT_NAME and tags.get("case_id") == CASE_ID and tags.get("gpu_id") == "synthetic-0":
            return alert.get("state")
    return None


def wait_for_state(lab, expected, timeout):
    end = time.monotonic() + timeout
    while True:
        state = current_alert(lab)
        if state == expected:
            return
        if time.monotonic() >= end:
            lab.block(f"Prometheus state {state!r} did not converge to {expected!r}")
        time.sleep(0.4)


def run(lab):
    for obj in resources(80):
        lab.create(obj)
    for name in (TELEMETRY_NAME, PROMETHEUS_NAME, TARGET_NAME, PROTECTED_NAME):
        wait_ready(lab, name)
    wait_for_metric(lab, 80)
    high_state = current_alert(lab)
    lab.check("red", "Observed active utilization keeps the rule clear and the fixture running",
              high_state is None and deployment(lab, TARGET_NAME)["spec"]["replicas"] == 1,
              {"observed_utilization_percent": 80, "idle_alert": high_state, "target_replicas": 1})

    lab.kubectl("patch", "configmap", TELEMETRY_NAME, "--type=merge",
                "-p", json.dumps({"data": {"metrics.prom": metrics(0)}}))
    lab.kubectl("rollout", "restart", f"deployment/{TELEMETRY_NAME}")
    lab.kubectl("rollout", "status", f"deployment/{TELEMETRY_NAME}", "--timeout=60s", timeout=65)
    wait_for_metric(lab, 0)
    wait_for_state(lab, "pending", 12)
    lab.check("positive", "The low utilization sample remains pending while the target is still running",
              deployment(lab, TARGET_NAME)["spec"]["replicas"] == 1,
              {"observed_utilization_percent": 0, "alert_state": "pending", "target_replicas": 1})
    wait_for_state(lab, "firing", 20)
    lab.check("green", "The specific synthetic idle rule fires after its required hold",
              current_alert(lab) == "firing",
              {"alert_state": "firing", "label": "synthetic-0", "threshold_percent": 5, "hold": "10s"})

    target = deployment(lab, TARGET_NAME)
    if target["metadata"]["labels"].get("saf.example/control") != CASE_ID or current_alert(lab) != "firing":
        lab.block("Reclamation requires the owned target and live matching alert")
    lab.kubectl("scale", f"deployment/{TARGET_NAME}", "--current-replicas=1", "--replicas=0")
    wait_for_target_pods_gone(lab)
    scaled = deployment(lab, TARGET_NAME)
    protected = deployment(lab, PROTECTED_NAME)
    lab.check("positive", "The exact synthetic target reaches zero with the protected workload still ready",
              scaled["spec"]["replicas"] == 0 and protected["spec"]["replicas"] == 1
              and protected["status"].get("readyReplicas", 0) == 1,
              {"target_replicas": scaled["spec"]["replicas"], "target_pods": 0,
               "protected_ready_replicas": protected["status"].get("readyReplicas", 0)})
