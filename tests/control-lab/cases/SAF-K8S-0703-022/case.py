"""Scrape two fixture feeds and evaluate review-only alert rules in Prometheus."""

import json
import importlib.util
from pathlib import Path
import time
from urllib.parse import urlencode

SCOPE = "Prometheus triage of invented activity and authorization context on an isolated Kind cluster."
PYTHON = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
PROM = "docker.io/prom/prometheus:v3.5.0@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996"
ACTIVITY = "fixture_gpu_activity_percent"
CONTEXT = "fixture_gpu_approved"
ACTIVITY_MAP = {"approved-intensive": 96, "policy-mismatch": 95, "missing-owner-context": 93, "low-activity": 15}
CONTEXT_MAP = {"approved-intensive": 1, "policy-mismatch": 0, "low-activity": 1}
EXPORTER = '''from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_error(404)
            return
        body = Path("/fixture/metrics").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''


def workload(lab, name, image, files, port, path, *, command=None, args=None):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "immutable": True, "data": files})
    container = {"name": name, "image": image, "ports": [{"containerPort": port, "name": "web"}],
                 "readinessProbe": {"httpGet": {"path": path, "port": "web"}, "periodSeconds": 1},
                 "resources": {"requests": {"cpu": "15m", "memory": "24Mi"}, "limits": {"cpu": "350m", "memory": "160Mi"}},
                 "volumeMounts": [{"name": "config", "mountPath": "/fixture", "readOnly": True},
                                  {"name": "scratch", "mountPath": "/data"}],
                 "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}}}
    if command:
        container["command"] = command
    if args:
        container["args"] = args
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {"app": name}},
                "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534,
                                             "fsGroup": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                         "containers": [container], "volumes": [{"name": "config", "configMap": {"name": name}},
                                                                  {"name": "scratch", "emptyDir": {}}]}})
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
                "spec": {"selector": {"app": name}, "ports": [{"name": "web", "port": port, "targetPort": "web"}]}})
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=65s", timeout=75)


def exporter(lab, name, metric, values):
    text = f"# TYPE {metric} gauge\n" + "".join(f'{metric}{{workload="{key}"}} {value}\n' for key, value in values.items())
    workload(lab, name, PYTHON, {"metrics": text, "exporter.py": EXPORTER}, 8080, "/metrics",
             command=["python", "/fixture/exporter.py"])


def prom_api(lab, endpoint):
    script = "from urllib.request import urlopen; import sys; print(urlopen(sys.argv[1],timeout=4).read().decode())"
    reply = lab.kubectl("exec", "fixture-activity", "--", "python", "-c", script,
                        "http://fixture-prometheus:9090" + endpoint, timeout=16, allow_failure=True)
    if reply.returncode:
        return None
    data = json.loads(reply.stdout)
    return data.get("data") if data.get("status") == "success" else None


def vector(lab, expression):
    result = prom_api(lab, "/api/v1/query?" + urlencode({"query": expression}))
    return {row["metric"]["workload"]: float(row["value"][1])
            for row in (result or {}).get("result", []) if "workload" in row["metric"]}


def rules():
    context_up = ' and on() (up{job="fixture-context"} == 1)'
    return {"groups": [{"name": "fixture-activity-triage", "rules": [
        {"alert": "FixturePolicyContextMismatch",
         "expr": f"({ACTIVITY} > 80 and on(workload) ({CONTEXT} == 0))" + context_up,
         "for": "3s", "labels": {"disposition": "review"}, "annotations": {"reason": "context-mismatch"}},
        {"alert": "FixtureMissingAuthorizationContext",
         "expr": f"({ACTIVITY} > 80 unless on(workload) {CONTEXT})" + context_up,
         "for": "3s", "labels": {"disposition": "review"}, "annotations": {"reason": "context-unknown"}},
    ]}]}


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    exporter(lab, "fixture-activity", ACTIVITY, ACTIVITY_MAP)
    exporter(lab, "fixture-context", CONTEXT, CONTEXT_MAP)
    prometheus = {"global": {"scrape_interval": "1s", "scrape_timeout": "800ms", "evaluation_interval": "1s"},
                  "rule_files": ["/fixture/rules.json"], "scrape_configs": [
                      {"job_name": target, "static_configs": [{"targets": [target + ":8080"]}]}
                      for target in ("fixture-activity", "fixture-context")]}
    workload(lab, "fixture-prometheus", PROM,
             {"prom.json": json.dumps(prometheus), "rules.json": json.dumps(rules())}, 9090, "/-/ready",
             args=["--config.file=/fixture/prom.json", "--storage.tsdb.path=/data"])
    expires = time.monotonic() + 50
    while time.monotonic() < expires:
        activity, authorization = vector(lab, ACTIVITY), vector(lab, CONTEXT)
        if activity == ACTIVITY_MAP and authorization == CONTEXT_MAP:
            break
        time.sleep(1)
    else:
        lab.block("Prometheus did not ingest both fixture feeds")
    threshold = vector(lab, ACTIVITY + " > 80")
    lab.check("red", "An activity-only rule also flags the explicitly approved high-activity fixture",
              set(threshold) == {"approved-intensive", "policy-mismatch", "missing-owner-context"},
              {"threshold_only_candidates": sorted(threshold)})
    expected = {"missing-owner-context": "context-unknown", "policy-mismatch": "context-mismatch"}
    expires = time.monotonic() + 30
    while time.monotonic() < expires:
        result = prom_api(lab, "/api/v1/alerts") or {}
        firing = {row["labels"]["workload"]: row["annotations"]["reason"] for row in result.get("alerts", [])
                  if row["state"] == "firing" and row["labels"].get("disposition") == "review"}
        if expected.items() <= firing.items():
            break
        time.sleep(1)
    else:
        lab.block("Prometheus did not fire the expected review alerts")
    lab.check("green", "Prometheus reports missing context and a policy mismatch as distinct review cases",
              firing == expected, {"firing_review_reasons": firing})
    positive = threshold["approved-intensive"] == 96 and authorization["approved-intensive"] == 1 and "approved-intensive" not in firing
    lab.check("positive", "The approved high-activity fixture remains observable without a review alert",
              positive, {"approved_activity_observed": positive, "low_activity_not_alerted": "low-activity" not in firing})
    (lab.evidence / "telemetry-triage-observations.json").write_text(json.dumps({
        "input_basis": "synthetic", "activity_samples": activity, "authorization_context": authorization,
        "activity_only_candidates": sorted(threshold), "review_alerts": firing,
    }, indent=2) + "\n")

    quality_path = Path(__file__).with_name("telemetry_quality.py")
    quality_spec = importlib.util.spec_from_file_location("saf_0703_022_telemetry_quality", quality_path)
    if quality_spec is None or quality_spec.loader is None:
        lab.block("Could not load the case-local telemetry freshness comparison")
    quality_module = importlib.util.module_from_spec(quality_spec)
    quality_spec.loader.exec_module(quality_module)
    quality_module.run(lab, workload, rules(), prom_api, vector)
