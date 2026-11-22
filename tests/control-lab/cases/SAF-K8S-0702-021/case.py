"""Verify native quota accounting through live Prometheus rule evaluation."""
import json
from pathlib import Path
import time
from urllib.parse import urlencode

from fixtures import container, pod, ready

SCOPE = (
    "Live v1.36.1 ResourceQuota status and kube-state-metrics scrape on local kind. "
    "Prometheus evaluates a live warning rule across bounded synthetic accelerator "
    "declarations and sees recovery. Hardware utilization, billing and notification "
    "delivery require separate evidence."
)
HERE = Path(__file__).parent
EXPORTER = (
    "registry.k8s.io/kube-state-metrics/kube-state-metrics:v2.20.0@sha256:"
    "42cfe3723a5f058171c627537fb57a3ea0f26e4380fa18555a95cb1a1b4cfc5b"
)
PROMETHEUS = (
    "docker.io/prom/prometheus:v3.16.0@sha256:"
    "e04987641b57704f408e31f6373ba4138ecf27cb4a165d24aabb6c38fddd0f06"
)
QUOTA = "synthetic-accelerator-budget"
GPU = "gpu.vendor.example/units"
KEY = f"requests.{GPU}"
HARD = "4"
MONITOR = "fixture-prometheus"
METRICS = "fixture-quota-metrics"
ALERT = "NamespaceExtendedResourceQuotaHigh"


def service(name, port):
    return {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
            "spec": {"selector": {"app": name}, "ports": [{"name": "http", "port": port}]}}


def create_monitoring(lab):
    objects = (
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": METRICS}},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": METRICS},
         "rules": [{"apiGroups": [""], "resources": ["resourcequotas"], "verbs": ["list", "watch"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": METRICS},
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": METRICS},
         "subjects": [{"kind": "ServiceAccount", "name": METRICS, "namespace": "saf-test"}]},
    )
    for obj in objects:
        lab.create(obj)
    exporter = pod(METRICS, [container("exporter", image=EXPORTER, command=["/kube-state-metrics"],
                                        args=["--namespaces=saf-test", "--resources=resourcequotas"])],
                   serviceAccountName=METRICS)
    exporter["metadata"]["labels"] = {"app": METRICS}
    lab.create(exporter)
    lab.create(service(METRICS, 8080))

    prometheus_config = (
        "global:\n  scrape_interval: 2s\n  evaluation_interval: 2s\n"
        "rule_files: [/etc/fixture/alerts.yml]\n"
        "scrape_configs:\n- job_name: fixture-quota\n  static_configs:\n"
        f"  - targets: ['{METRICS}:8080']\n"
    )
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": MONITOR},
                "data": {"prometheus.yml": prometheus_config, "alerts.yml": (HERE / "alerts.yml").read_text()}})
    prometheus = container(
        "prometheus", image=PROMETHEUS, command=["/bin/prometheus"],
        args=["--config.file=/etc/fixture/prometheus.yml", "--storage.tsdb.path=/prometheus",
              "--web.listen-address=:9090"],
        volumeMounts=[{"name": "config", "mountPath": "/etc/fixture", "readOnly": True},
                      {"name": "data", "mountPath": "/prometheus"}])
    recorder = pod(MONITOR, [prometheus], automountServiceAccountToken=False,
                   securityContext={"fsGroup": 65534},
                   volumes=[{"name": "config", "configMap": {"name": MONITOR}},
                            {"name": "data", "emptyDir": {}}])
    recorder["metadata"]["labels"] = {"app": MONITOR}
    lab.create(recorder)
    lab.create(service(MONITOR, 9090))
    ready(lab, METRICS)
    ready(lab, MONITOR)


def accelerator_pod(name, units):
    return pod(name, [container("inert", resources={"requests": {GPU: str(units)},
                                                    "limits": {GPU: str(units)}})],
               automountServiceAccountToken=False)


def query(lab, expression):
    path = f"/api/v1/namespaces/saf-test/services/http:{MONITOR}:http/proxy/api/v1/query"
    result = lab.kubectl("get", f"--raw={path}?{urlencode({'query': expression})}",
                         allow_failure=True, timeout=15)
    if result.returncode:
        return None
    response = json.loads(result.stdout)
    if response.get("status") != "success":
        lab.block("The owned Prometheus service returned an unsuccessful query")
    return [series["value"][1] for series in response["data"]["result"]]


def check_signal(lab, phase, wanted_used, firing, claim):
    tags = f'namespace="saf-test",resourcequota="{QUOTA}",resource="{KEY}"'
    deadline = time.monotonic() + 45
    observed = {}
    while time.monotonic() < deadline:
        quota = json.loads(lab.kubectl("get", "resourcequota", QUOTA, "-o", "json").stdout)["status"]
        used = query(lab, f'kube_resourcequota{{{tags},type="used"}}')
        hard = query(lab, f'kube_resourcequota{{{tags},type="hard"}}')
        active = query(lab, f'ALERTS{{{tags},alertname="{ALERT}",alertstate="firing"}}')
        observed = {"quota_used": quota.get("used", {}).get(KEY), "quota_hard": quota.get("hard", {}).get(KEY),
                    "prometheus_used": used, "prometheus_hard": hard, "firing": active}
        expected = {"quota_used": wanted_used, "quota_hard": HARD, "prometheus_used": [wanted_used],
                    "prometheus_hard": [HARD], "firing": ["1"] if firing else []}
        if observed == expected:
            lab.check(phase, claim, True, observed)
            return
        time.sleep(1)
    lab.check(phase, claim, False, observed)


def run(lab):
    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    if any(GPU in node["status"].get("allocatable", {}) for node in nodes):
        lab.block("The lab fixture requires an unadvertised synthetic resource")

    lab.create({"apiVersion": "v1", "kind": "ResourceQuota", "metadata": {"name": QUOTA},
                "spec": {"hard": {KEY: HARD}}})
    create_monitoring(lab)
    check_signal(lab, "red", "0", False, "The live quota metrics are present and the unused quota has no firing alert")
    lab.create(accelerator_pod("synthetic-accelerator-low", 1))
    check_signal(lab, "positive", "1", False, "One declared unit is scraped and stays below the threshold")
    lab.create(accelerator_pod("synthetic-accelerator-high", 2))
    check_signal(lab, "green", "3", True, "Prometheus fires at 75 percent while quota headroom remains")
    observations = json.loads(lab.kubectl("get", "pod", "synthetic-accelerator-low",
                                          "synthetic-accelerator-high", "-o", "json").stdout)["items"]
    pending = sorted(item["metadata"]["name"] for item in observations
                     if item["status"].get("phase") == "Pending")
    lab.check("positive", "Both inert declarations remain Pending with no advertised accelerator",
              pending == ["synthetic-accelerator-high", "synthetic-accelerator-low"], pending)
    lab.kubectl("delete", "pod", "synthetic-accelerator-high", "--wait=true")
    check_signal(lab, "green", "1", False, "The live warning clears when declared quota usage drops to 25 percent")
