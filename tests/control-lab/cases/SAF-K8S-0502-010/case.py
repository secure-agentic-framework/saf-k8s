"""Exercise Service and Pod IP allocator capacity warnings on an isolated Kind cluster."""
import ipaddress
import json
import re
import runpy
import subprocess
import time
from pathlib import Path
from urllib.parse import quote_plus


NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
SERVICE_CIDR = "10.97.240.0/28"
LOW_FREE_FRACTION = 0.50
MAX_FIXTURES = 8
METRICS = {
    "allocated": "kube_apiserver_clusterip_allocator_allocated_ips",
    "available": "kube_apiserver_clusterip_allocator_available_ips",
}
PREFIX = "saf-0502-010-"
MONITOR = "service-ipam-prometheus"
ALERT = "KubernetesServiceIPPoolLow"
BUSYBOX_IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
PROMETHEUS_IMAGE = (
    "docker.io/prom/prometheus:v3.16.0@sha256:"
    "e04987641b57704f408e31f6373ba4138ecf27cb4a165d24aabb6c38fddd0f06"
)
SCOPE = (
    "Kubernetes v1.36.1 on one disposable Kind cluster with small dedicated IPv4 Service and Pod ranges. "
    "Reads the API server's native Service ClusterIP allocator metrics and the owned node's kindnet "
    "host-local Pod lease files. Prometheus fires each warning before its pool is full, a further owned "
    "Service or Pod receives an address, and deleting only the fixtures clears each warning. "
    "The Kind node underlay is inventoried separately. Provider address pools, other CNIs and external "
    "alert delivery are outside this probe."
)


def metric_series(lab):
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
               "--request-timeout=8s", "get", "--raw", "/metrics"]
    result = subprocess.run(command, env=lab.env, capture_output=True, text=True, timeout=12)
    if result.returncode:
        lab.block("The owned Kubernetes API did not return allocator metrics")
    raw = result.stdout
    found = {name: [] for name in METRICS.values()}
    for line in raw.splitlines():
        match = re.match(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+([^\s]+)", line)
        if not match or match.group(1) not in found:
            continue
        labels = dict(re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"',
                                 match.group(2) or ""))
        if labels.get("cidr") == SERVICE_CIDR:
            found[match.group(1)].append(float(match.group(3)))
    result = {}
    for key, name in METRICS.items():
        if len(found[name]) != 1 or found[name][0] < 0:
            lab.block(f"Expected one nonnegative {name} sample for {SERVICE_CIDR}")
        result[key] = found[name][0]
    return result


def wait_metrics(lab, predicate, description, timeout=20):
    deadline = time.monotonic() + timeout
    latest = None
    while time.monotonic() < deadline:
        latest = metric_series(lab)
        if predicate(latest):
            return latest
        time.sleep(0.5)
    lab.block(f"Timed out waiting for {description}; metrics={latest}")


def pressured(sample):
    total = sample["allocated"] + sample["available"]
    return total > 0 and sample["available"] / total < LOW_FREE_FRACTION


def service_resource(name, address):
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": name,
            "namespace": "saf-test",
            "labels": {"saf-k8s-control": "SAF-K8S-0502-010", "saf-owned": "true"},
        },
        "spec": {
            "type": "ClusterIP",
            "clusterIP": str(address),
            "ports": [{"name": "harmless", "port": 80, "targetPort": 8080}],
            "selector": {"saf-k8s-control": "SAF-K8S-0502-010-no-backend"},
        },
    }


def owned_services(lab):
    data = json.loads(lab.kubectl(
        "get", "services", "-l", "saf-k8s-control=SAF-K8S-0502-010", "-o", "json"
    ).stdout)
    names = []
    for item in data["items"]:
        metadata = item.get("metadata", {})
        name = metadata.get("name", "")
        if metadata.get("namespace") != "saf-test" or not name.startswith(PREFIX):
            lab.block("Refusing cleanup: found a Service outside this case's ownership labels")
        names.append(name)
    return names


def verify_allocated(lab, service, name):
    address = ipaddress.ip_address(service["spec"]["clusterIP"])
    registered = json.loads(lab.kubectl("get", "ipaddress", str(address), "-o", "json").stdout)
    parent = registered["spec"]["parentRef"]
    if address not in ipaddress.ip_network(SERVICE_CIDR) or (
        parent.get("resource"), parent.get("namespace"), parent.get("name")
    ) != ("services", "saf-test", name):
        lab.block("The allocated API address did not refer to the exact owned Service")
    return address


def start_monitor(lab):
    account = "/var/run/secrets/kubernetes.io/serviceaccount"
    configuration = f"""global:
  scrape_interval: 2s
  evaluation_interval: 2s
rule_files:
- /fixture/alerts.yml
scrape_configs:
- job_name: owned-apiserver
  scheme: https
  authorization:
    credentials_file: {account}/token
  tls_config:
    ca_file: {account}/ca.crt
  static_configs:
  - targets: ["kubernetes.default.svc:443"]
- job_name: owned-pod-ipam-sample
  fallback_scrape_protocol: PrometheusText0.0.4
  static_configs:
  - targets: ["127.0.0.1:9091"]
"""
    specs = [
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": MONITOR}},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
         "metadata": {"name": MONITOR},
         "rules": [{"nonResourceURLs": ["/metrics"], "verbs": ["get"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
         "metadata": {"name": MONITOR},
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": MONITOR},
         "subjects": [{"kind": "ServiceAccount", "name": MONITOR, "namespace": "saf-test"}]},
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": MONITOR},
         "data": {"prometheus.yml": configuration, "alerts.yml": Path(__file__).with_name("alerts.yml").read_text()}},
        {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": MONITOR, "labels": {"app": MONITOR}},
         "spec": {"serviceAccountName": MONITOR,
                  "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534,
                                      "seccompProfile": {"type": "RuntimeDefault"}},
                  "containers": [{
                      "name": "monitor", "image": PROMETHEUS_IMAGE,
                      "args": ["--config.file=/fixture/prometheus.yml", "--storage.tsdb.path=/data",
                               "--storage.tsdb.retention.time=1h"],
                      "ports": [{"name": "web", "containerPort": 9090}],
                      "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
                      "readinessProbe": {"httpGet": {"path": "/-/ready", "port": "web"}},
                      "volumeMounts": [{"name": "config", "mountPath": "/fixture", "readOnly": True},
                                       {"name": "data", "mountPath": "/data"}],
                  }, {
                      "name": "pod-ipam-exporter", "image": BUSYBOX_IMAGE,
                      "command": ["httpd", "-f", "-p", "127.0.0.1:9091", "-h", "/samples"],
                      "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                          "capabilities": {"drop": ["ALL"]}},
                      "volumeMounts": [{"name": "pod-samples", "mountPath": "/samples"}],
                  }],
                  "volumes": [{"name": "config", "configMap": {"name": MONITOR}},
                              {"name": "data", "emptyDir": {}},
                              {"name": "pod-samples", "emptyDir": {}}]}},
        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": MONITOR},
         "spec": {"selector": {"app": MONITOR}, "ports": [{"name": "web", "port": 9090}]}},
    ]
    for resource in specs:
        lab.create(resource)
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{MONITOR}", "--timeout=90s", timeout=100)


def query(lab, expression):
    route = (f"/api/v1/namespaces/saf-test/services/http:{MONITOR}:web/proxy"
             f"/api/v1/query?query={quote_plus(expression)}")
    response = lab.kubectl("get", "--raw", route, allow_failure=True, timeout=12)
    if response.returncode:
        return None
    body = json.loads(response.stdout)
    if body.get("status") != "success":
        lab.block("The case-owned Prometheus did not complete an allocator query")
    return [float(row["value"][1]) for row in body["data"]["result"]]


def observe_monitor(lab, sample, firing):
    deadline = time.monotonic() + 30
    metric_label = f'{{cidr="{SERVICE_CIDR}"}}'
    alert = f'ALERTS{{alertname="{ALERT}",alertstate="firing",cidr="{SERVICE_CIDR}"}}'
    while time.monotonic() < deadline:
        scrape = {key: query(lab, name + metric_label) for key, name in METRICS.items()}
        alert_state = query(lab, alert)
        if scrape == {key: [value] for key, value in sample.items()}:
            if alert_state == ([1.0] if firing else []):
                return "firing" if firing else "inactive"
        time.sleep(0.25)
    lab.block(f"Prometheus did not match the current allocator sample and expected firing state {firing}")


def run(lab):
    version = json.loads(lab.kubectl("version", "-o", "json").stdout)
    server = version.get("serverVersion", {}).get("gitVersion", "")
    if not server.startswith("v1.36."):
        lab.block(f"Expected a Kubernetes v1.36 server, got {server!r}")

    cidr_name = "saf-ipam-warning-range"
    lab.create({"apiVersion": "networking.k8s.io/v1", "kind": "ServiceCIDR",
                "metadata": {"name": cidr_name}, "spec": {"cidrs": [SERVICE_CIDR]}})
    lab.kubectl("wait", "--for=condition=Ready", f"servicecidr/{cidr_name}", "--timeout=35s", timeout=43)
    cidr_rows = json.loads(lab.kubectl("get", "servicecidr", "-o", "json").stdout)["items"]
    matching = [row for row in cidr_rows
                if SERVICE_CIDR in row.get("spec", {}).get("cidrs", [])]
    if len(matching) != 1:
        lab.block(f"Expected exactly one ServiceCIDR for {SERVICE_CIDR}")

    start_monitor(lab)
    addresses = list(ipaddress.ip_network(SERVICE_CIDR).hosts())
    sentinel_name = "saf-ipam-baseline"
    sentinel = service_resource(sentinel_name, addresses[0])
    sentinel["metadata"]["labels"]["saf-k8s-control"] = "SAF-K8S-0502-010-baseline"
    verify_allocated(lab, lab.create(sentinel), sentinel_name)

    def registered_service_count():
        objects = json.loads(lab.kubectl("get", "ipaddresses", "-o", "json").stdout)["items"]
        pool = ipaddress.ip_network(SERVICE_CIDR)
        return sum(ipaddress.ip_address(item["metadata"]["name"]) in pool
                   and item["spec"]["parentRef"]["resource"] == "services" for item in objects)

    baseline = wait_metrics(lab, lambda value: value["allocated"] == registered_service_count() == 1,
                            "native allocator gauge to match the live Service IPAddress registrations")
    if pressured(baseline):
        lab.block("The initial case ServiceCIDR is already below the exercise threshold")
    initial_alert = observe_monitor(lab, baseline, False)
    if baseline["available"] <= 2 or baseline["allocated"] < 1:
        lab.block(f"ServiceCIDR has insufficient spare capacity for a safe probe: {baseline}")
    lab.check(
        "positive", "The API exposes native allocator gauges for the case ServiceCIDR",
        baseline["available"] > 0 and baseline["allocated"] > 0,
        {"service_cidr": SERVICE_CIDR, "gauge_matched_current_ipaddress_registrations": True,
         "metric_scope": "Service ClusterIP allocator only", "alert_state": initial_alert},
    )

    planned_limit = min(MAX_FIXTURES + 1, int(baseline["available"]) - 2)
    if planned_limit < 4:
        lab.block("The case has insufficient measured capacity to preserve two available addresses")
    created = []
    allocated = set()
    try:
        pressured_sample = None
        for index in range(planned_limit - 1):
            if metric_series(lab)["available"] <= 2:
                lab.block("The bounded fixture must retain allocation headroom")
            name = f"{PREFIX}{index:02d}"
            created.append(name)
            response = lab.create(service_resource(name, addresses[index + 1]))
            address = verify_allocated(lab, response, name)
            if address in allocated:
                lab.block("The allocator returned a duplicate owned Service address")
            allocated.add(address)
            sample = metric_series(lab)
            if pressured(sample):
                pressured_sample = sample
                break

        if pressured_sample is None:
            lab.block(f"Did not cross the {LOW_FREE_FRACTION:.0%} free-capacity threshold within the fixture bound")
        alert_state = observe_monitor(lab, pressured_sample, True)
        lab.check(
            "red", "Low-free-capacity rule is active before the Service pool is exhausted",
            pressured(pressured_sample) and pressured_sample["available"] > 1,
            {"free_fraction_below_threshold": pressured(pressured_sample),
             "free_addresses_remain": pressured_sample["available"] > 1, "alert_state": alert_state,
             "owned_address_objects_verified": bool(allocated)},
        )

        extra_name = f"{PREFIX}extra"
        created.append(extra_name)
        response = lab.create(service_resource(extra_name, addresses[-1]))
        extra_address = verify_allocated(lab, response, extra_name)
        if extra_address in allocated:
            lab.block("The final Service reused an occupied fixture address")
        after_extra = wait_metrics(
            lab, lambda value: pressured(value) and value["available"] > 0,
            "allocator pressure after the additional confirmed Service",
        )
        extra_alert = observe_monitor(lab, after_extra, True)
        lab.check(
            "positive", "A further ClusterIP Service is accepted while the low-capacity rule is active",
            pressured(after_extra) and after_extra["available"] > 0,
            {"free_addresses_remain": after_extra["available"] > 0, "extra_service": extra_name,
             "unique_ip_address_object_verified": True,
             "alert_state": extra_alert},
        )
    finally:
        # Restrict deletion to names returned by the case's ownership selector.
        actual = set(owned_services(lab))
        for name in created:
            if name in actual:
                lab.kubectl("delete", "service", name, "--wait=true")

    recovered = wait_metrics(
        lab,
        lambda value: not pressured(value) and value["allocated"] == baseline["allocated"],
        "allocator gauges and alert expression to recover after fixture deletion",
    )
    remaining = owned_services(lab)
    recovered_alert = observe_monitor(lab, recovered, False)
    snapshots = {"baseline": baseline, "threshold": pressured_sample,
                 "after_extra": after_extra, "recovered": recovered}
    (lab.evidence / "allocator-samples.json").write_text(json.dumps(snapshots, indent=2) + "\n")
    lab.check(
        "green", "Deleting only case-owned Services clears the alert condition and restores baseline allocation",
        not pressured(recovered) and recovered["allocated"] == baseline["allocated"] and not remaining,
        {"baseline_allocation_restored": recovered["allocated"] == baseline["allocated"],
         "remaining_owned_services": remaining, "alert_state": recovered_alert},
    )

    pod_ipam = runpy.run_path(str(Path(__file__).with_name("pod_ipam.py")))
    pod_ipam["verify"](lab, query, MONITOR, BUSYBOX_IMAGE)
