"""Exercise native Prometheus Operator discovery for synthetic AI workloads."""
import hashlib
import json
import re
import time
import urllib.parse
import urllib.request

NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
OPERATOR_IMAGE = "quay.io/prometheus-operator/prometheus-operator:v0.85.0@sha256:890b3bb05cf4ed81541922c611de8805ec9f5c1428017738a8e64e9189350e80"
RELOADER_IMAGE = "quay.io/prometheus-operator/prometheus-config-reloader:v0.85.0@sha256:ebb560bcb6bd3ab728a7ab61d77d22a001cc0c7a67f0531e7f92e20ce004de38"
PROMETHEUS_IMAGE = "docker.io/prom/prometheus:v3.5.0@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996"
PYTHON_IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
NS = "saf-test"
SCOPE = (
    "A disposable Kubernetes v1.36.1 Kind cluster reconciles native Prometheus Operator "
    "Prometheus, ServiceMonitor, and PodMonitor resources. Namespace-scoped discovery RBAC "
    "and selector labels limit scraping to two safe synthetic CPU workloads. Prometheus API "
    "queries prove no samples before monitor enrollment and exact per-workload stage, measured "
    "latency, and quality markers after enrollment. This does not prove NVIDIA hardware, "
    "DCGM exporter metrics, or instrumentation in native training or serving frameworks."
)

BUNDLE = "https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/v0.85.0/bundle.yaml"
BUNDLE_SHA256 = "602f3a0c4f91952cfbbaedeed6542a8231134537191965275b9e2c2e05aeab72"
APP = r'''import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

workload = os.environ["WORKLOAD"]
progress = 0
duration = 0
if workload == "saf-training":
    started = time.perf_counter()
    weight = 0.0
    for _ in range(3):
        for feature, expected in ((-1, -2), (1, 2), (2, 4)):
            weight += 0.1 * (expected - feature * weight) * feature
        progress += 1
    duration = max(time.perf_counter() - started, 0.000000001)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_error(404)
            return
        key = f'fixture="1002-003",workload="{workload}"'
        if workload == "saf-training":
            values = (
                ("saf_training_stage", key + ',stage="epoch"', progress),
                ("saf_stage_duration_seconds", key, duration),
            )
        else:
            features = (-3, -2, -1, 0, 1, 2, 3, 4)
            expected = (0, 0, 0, 0, 1, 1, 1, 0)
            started = time.perf_counter()
            predicted = [int(item > 0) for item in features]
            latency = max(time.perf_counter() - started, 0.000000001)
            quality = sum(a == b for a, b in zip(predicted, expected)) / len(expected)
            values = (
                ("saf_inference_latency_seconds", key, latency),
                ("saf_model_quality_marker", key + ',model="synthetic-v1"', quality),
            )
        lines = []
        for name, labels, value in values:
            lines.extend((f"# TYPE {name} gauge", f"{name}{{{labels}}} {value}"))
        body = ("\n".join(lines) + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''


def obj(api, kind, name, **fields):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields}


def _security():
    return {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True, "runAsUser": 65534,
            "seccompProfile": {"type": "RuntimeDefault"}}


def _json(lab, url):
    script = "import json,urllib.request; print(urllib.request.urlopen(%r,timeout=8).read().decode())" % url
    return json.loads(lab.kubectl("exec", "pod/saf-query", "--", "python", "-c", script,
                                  timeout=20).stdout)


def _query(lab, expression):
    url = "http://saf-prometheus:9090/api/v1/query?" + urllib.parse.urlencode({"query": expression})
    reply = _json(lab, url)
    if reply.get("status") != "success":
        lab.block("Prometheus query API did not return success")
    return reply["data"]["result"]


def _wait(lab, expression, predicate, seconds=100):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        rows = _query(lab, expression)
        if predicate(rows):
            return rows
        time.sleep(2)
    return _query(lab, expression)


def _release_specs(lab):
    local = lab.kubeconfig.parent / "prometheus-operator-bundle.yaml"
    lab.command("curl", "--fail", "--silent", "--show-error", "--location", BUNDLE,
                "-o", str(local), timeout=45)
    release = local.read_bytes()
    if hashlib.sha256(release).hexdigest() != BUNDLE_SHA256:
        lab.block("The downloaded Prometheus Operator bundle differs from the pinned release")
    documents = re.split(r"^---[ \t]*$", release.decode(), flags=re.M)
    crds = [doc for doc in documents if "\nkind: CustomResourceDefinition\n" in doc]
    roles = [doc for doc in documents if "\nkind: ClusterRole\n" in doc]
    if len(crds) != 10 or len(roles) != 1:
        lab.block("Unexpected definitions in the tagged upstream bundle")
    lab.kubectl("apply", "--server-side", "-f", "-", payload="---".join(crds), timeout=80)
    for doc in crds:
        name = re.search(r"^  name: ([^\s]+)$", doc, re.M).group(1)
        lab.kubectl("wait", "--for=condition=Established", f"crd/{name}", "--timeout=45s", timeout=50)
    lab.kubectl("apply", "--server-side", "-f", "-", payload=roles[0], timeout=30)


def _install_operator(lab):
    lab.create(obj("v1", "ServiceAccount", "saf-operator"))
    lab.create(obj("v1", "ServiceAccount", "saf-prometheus"))
    lab.create(obj("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "saf-operator",
                   roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "prometheus-operator"},
                   subjects=[{"kind": "ServiceAccount", "name": "saf-operator", "namespace": NS}]))
    lab.create(obj("rbac.authorization.k8s.io/v1", "Role", "saf-prometheus-discovery", rules=[
        {"apiGroups": [""], "resources": ["services", "endpoints", "pods"], "verbs": ["get", "list", "watch"]},
        {"apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"], "verbs": ["get", "list", "watch"]}]))
    lab.create(obj("rbac.authorization.k8s.io/v1", "RoleBinding", "saf-prometheus-discovery",
                   roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "saf-prometheus-discovery"},
                   subjects=[{"kind": "ServiceAccount", "name": "saf-prometheus", "namespace": NS}]))
    lab.create({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "saf-operator"}, "spec": {
        "replicas": 1, "selector": {"matchLabels": {"app": "saf-operator"}}, "template": {"metadata": {"labels": {"app": "saf-operator"}}, "spec": {
            "serviceAccountName": "saf-operator", "automountServiceAccountToken": True,
            "containers": [{"name": "operator", "image": OPERATOR_IMAGE,
                "args": ["--kubelet-service=", "--prometheus-config-reloader=" + RELOADER_IMAGE,
                         "--namespaces=" + NS, "--prometheus-instance-namespaces=" + NS],
                "resources": {"requests": {"cpu": "25m", "memory": "64Mi"}, "limits": {"cpu": "300m", "memory": "192Mi"}}, "securityContext": _security()}]}}}})
    lab.kubectl("rollout", "status", "deployment/saf-operator", "--timeout=120s", timeout=130)


def _workload(lab, name):
    labels = {"app": name, "saf.synthetic": "true"}
    lab.create(obj("v1", "ConfigMap", name + "-code", data={"app.py": APP}))
    lab.create({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name}, "spec": {
        "replicas": 1, "selector": {"matchLabels": labels}, "template": {"metadata": {"labels": labels}, "spec": {
            "automountServiceAccountToken": False,
            "containers": [{"name": "app", "image": PYTHON_IMAGE,
                "command": ["python", "/fixture/app.py"], "env": [{"name": "WORKLOAD", "value": name}],
                "ports": [{"name": "metrics", "containerPort": 8080}],
                "readinessProbe": {"httpGet": {"path": "/metrics", "port": "metrics"}, "periodSeconds": 2},
                "resources": {"requests": {"cpu": "10m", "memory": "32Mi"}, "limits": {"cpu": "100m", "memory": "96Mi"}},
                "volumeMounts": [{"name": "code", "mountPath": "/fixture", "readOnly": True}], "securityContext": _security()}],
            "volumes": [{"name": "code", "configMap": {"name": name + "-code"}}]}}}})
    service = obj("v1", "Service", name, spec={
        "selector": labels, "ports": [{"name": "metrics", "port": 8080, "targetPort": "metrics"}],
    })
    service["metadata"]["labels"] = labels
    lab.create(service)
    lab.kubectl("rollout", "status", f"deployment/{name}", "--timeout=100s", timeout=110)


def _prometheus(lab):
    lab.create({"apiVersion": "monitoring.coreos.com/v1", "kind": "Prometheus", "metadata": {"name": "saf-prometheus", "labels": {"saf.synthetic": "true"}}, "spec": {
        "replicas": 1, "version": "3.5.0", "image": PROMETHEUS_IMAGE, "serviceAccountName": "saf-prometheus",
        "serviceMonitorSelector": {"matchLabels": {"saf.synthetic": "true"}},
        "serviceMonitorNamespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": NS}},
        "podMonitorSelector": {"matchLabels": {"saf.synthetic": "true"}},
        "podMonitorNamespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": NS}},
        "resources": {"requests": {"cpu": "100m", "memory": "256Mi"}, "limits": {"cpu": "500m", "memory": "512Mi"}},
        "serviceDiscoveryRole": "EndpointSlice", "scrapeInterval": "4s", "retention": "1h"}})
    lab.create(obj("v1", "Service", "saf-prometheus", spec={"selector": {"prometheus": "saf-prometheus"}, "ports": [{"name": "web", "port": 9090, "targetPort": "web"}]}))


def run(lab):
    for name in ("training", "inference", "comparison"):
        _workload(lab, "saf-" + name)
    # Local query client avoids needing host port publishing and sends no probes outside Kind.
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "saf-query"}, "spec": {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "containers": [{"name": "query", "image": PYTHON_IMAGE,
                        "command": ["python", "-c", "import time; time.sleep(3600)"],
                        "resources": {"requests": {"cpu": "5m", "memory": "16Mi"}, "limits": {"cpu": "50m", "memory": "64Mi"}},
                        "securityContext": _security()}]}})
    lab.kubectl("wait", "--for=condition=Ready", "pod/saf-query", "--timeout=90s", timeout=100)
    _release_specs(lab)
    _install_operator(lab)
    _prometheus(lab)
    lab.kubectl("wait", "--for=create", "statefulset/prometheus-saf-prometheus", "--timeout=90s", timeout=95)
    lab.kubectl("rollout", "status", "statefulset/prometheus-saf-prometheus", "--timeout=120s", timeout=130)
    lab.kubectl("wait", "--for=condition=Ready", "pod", "-l", "prometheus=saf-prometheus", "--timeout=150s", timeout=160)
    selectors = {
        "saf_training_stage": "saf-training",
        "saf_stage_duration_seconds": "saf-training",
        "saf_inference_latency_seconds": "saf-inference",
        "saf_model_quality_marker": "saf-inference",
    }
    identities = {name: '{fixture="1002-003"}' for name in selectors}
    before = {name: _query(lab, name + filter_) for name, filter_ in identities.items()}
    first_targets = _json(lab, "http://saf-prometheus:9090/api/v1/targets")["data"]["activeTargets"]
    lab.check("red", "Before monitor enrollment healthy fixture workloads have no scrape targets or samples",
              not any(before.values()) and not first_targets,
              {"sample_sets": sum(map(bool, before.values())), "active_targets": len(first_targets)})
    hosts = {name: f"http://saf-{name}:8080/metrics" for name in ("training", "inference", "comparison")}
    direct_script = "import sys,urllib.request; print(urllib.request.urlopen(sys.argv[1],timeout=6).read().decode())"
    sources = {
        name: lab.kubectl("exec", "pod/saf-query", "--", "python", "-c", direct_script, url, timeout=20).stdout
        for name, url in hosts.items()
    }
    namespace = {"matchNames": [NS]}
    labels = {"saf.synthetic": "true"}
    lab.create({"apiVersion": "monitoring.coreos.com/v1", "kind": "ServiceMonitor",
                "metadata": {"name": "training", "labels": labels},
                "spec": {"selector": {"matchLabels": {"app": "saf-training"}},
                         "namespaceSelector": namespace,
                         "endpoints": [{"port": "metrics", "path": "/metrics", "interval": "4s"}]}})
    lab.create({"apiVersion": "monitoring.coreos.com/v1", "kind": "PodMonitor",
                "metadata": {"name": "inference", "labels": labels},
                "spec": {"selector": {"matchLabels": {"app": "saf-inference"}},
                         "namespaceSelector": namespace,
                         "podMetricsEndpoints": [{"port": "metrics", "path": "/metrics", "interval": "4s"}]}})

    results = {name: _wait(lab, name + filter_, lambda rows: len(rows) == 1, seconds=80)
               for name, filter_ in identities.items()}
    values = {name: [(row["metric"].get("workload"), float(row["value"][1])) for row in rows]
              for name, rows in results.items()}
    one_each = all(len(values[name]) == 1 and values[name][0][0] == source
                   for name, source in selectors.items())
    exact = (one_each and values["saf_training_stage"][0][1] == 3
             and values["saf_model_quality_marker"][0][1] == 0.875
             and all(0 < values[name][0][1] < 1
                     for name in ("saf_stage_duration_seconds", "saf_inference_latency_seconds")))
    lab.check("green", "The native monitors expose exact training progress, measured timings, and labeled model quality",
              exact, {"four_unique_expected_series": one_each, "training_epochs": 3,
                      "quality_marker": 0.875, "measured_timings_within_bounds": exact})
    active = _json(lab, "http://saf-prometheus:9090/api/v1/targets")["data"]["activeTargets"]
    pools = {row["scrapePool"]: row["health"] for row in active}
    expected = {"serviceMonitor/saf-test/training/0": "up", "podMonitor/saf-test/inference/0": "up"}
    compare_rows = _query(lab, '{fixture="1002-003",workload="saf-comparison"}')
    lab.check("positive", "ServiceMonitor and PodMonitor produce separate scrapes and leave the healthy unselected fixture out",
              len(active) == 2 and pools == expected and not compare_rows
              and 'workload="saf-comparison"' in sources["comparison"],
              {"pools": pools, "unselected_samples": len(compare_rows), "direct_comparator_healthy": True})
    impersonate = "--as=system:serviceaccount:saf-test:saf-prometheus"
    inside = lab.kubectl("auth", "can-i", "list", "endpointslices.discovery.k8s.io", impersonate,
                         allow_failure=True)
    outside = lab.kubectl("-n", "default", "auth", "can-i", "list", "endpointslices.discovery.k8s.io",
                          impersonate, allow_failure=True)
    secrets = lab.kubectl("auth", "can-i", "get", "secrets", impersonate, allow_failure=True)
    decisions = {"fixture_endpointslices": inside.stdout.strip(), "other_endpointslices": outside.stdout.strip(),
                 "fixture_secrets": secrets.stdout.strip()}
    lab.check("positive", "The scraping identity is scoped to discovery in the fixture namespace",
              decisions == {"fixture_endpointslices": "yes", "other_endpointslices": "no", "fixture_secrets": "no"}
              and inside.returncode == 0 and outside.returncode != 0 and secrets.returncode != 0, decisions)
    raw = {"bundle_sha256": BUNDLE_SHA256, "sources": sources, "before": before,
           "first_targets": first_targets, "samples": results, "target_status": active,
           "unselected_samples": compare_rows, "discovery_rbac": decisions}
    (lab.evidence / "telemetry-observed.json").write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
