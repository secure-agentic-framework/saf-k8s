"""Measure actual Pod and Service routes to a case-owned OCI registry."""
import importlib.util
import json
from pathlib import Path
import time

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent
REGISTRY_IMAGE = (
    "docker.io/library/registry:3.0.0@sha256:"
    "6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
)
REGISTRY = "fixture-network-registry"
CLIENTS = {"trusted": "fixture-registry-approved", "untrusted": "fixture-registry-other"}
POLICY = "fixture-limit-registry-sources"
SCOPE = (
    "Measure a pinned Distribution registry with real OCI API reads through both a ClusterIP Service "
    "and the registry Pod address. Compare the same two case-owned calling pods before and after "
    "kindnet enforces NetworkPolicy. Verify separate reads for the authorized source. "
    "This covers the in-cluster registry entry points and selected identities only."
)
PROBE = r"""
from http.client import HTTPConnection
import json
import sys
try:
    with_connection = HTTPConnection(sys.argv[1], 5000, timeout=1.75)
    with_connection.request("GET", "/v2/")
    response = with_connection.getresponse()
    result = {"endpoint": response.status,
              "registry_api": response.getheader("Docker-Distribution-API-Version"),
              "payload": json.load(response)}
except TimeoutError:
    result = {"outcome": "timeout"}
except OSError as error:
    result = {"outcome": type(error).__name__}
print(json.dumps(result, sort_keys=True))
"""
REACHABLE = {"endpoint": 200, "registry_api": "registry/2.0", "payload": {}}


def hit(lab, client, address):
    raw = lab.kubectl("exec", client, "--", "python", "-c", PROBE, address, timeout=12)
    return json.loads(raw.stdout)


def run(lab):
    f = HERE.parent / "SAF-K8S-0908-001" / "case.py"
    spec = importlib.util.spec_from_file_location("saf_registry_network_runtime", f)
    if spec is None or spec.loader is None:
        lab.block("The pinned runtime loader could not be imported")
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    image = runtime.load_runtime(lab)

    system = json.loads(lab.kubectl("-n", "kube-system", "get", "ds", "kindnet", "-o", "json").stdout)
    if system["status"].get("numberReady", 0) < 1:
        lab.block("The planned kindnet network-policy provider is unavailable")
    labels = {"app": REGISTRY}
    endpoint = container("registry", image=REGISTRY_IMAGE, ports=[{"containerPort": 5000}],
                         env=[{"name": "REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY",
                               "value": "/tmp/saf-registry"}])
    del endpoint["command"]
    endpoint["readinessProbe"] = {"httpGet": {"port": 5000, "path": "/v2/"}, "periodSeconds": 1}
    backend = pod(REGISTRY, [endpoint], automountServiceAccountToken=False)
    backend["metadata"]["labels"] = labels
    lab.create(backend)
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": REGISTRY},
                "spec": {"selector": labels, "ports": [{"port": 5000, "targetPort": 5000}]}})
    for source, name in CLIENTS.items():
        request = pod(name, [container("probe", image=image, imagePullPolicy="Never",
                                       command=["sleep", "3600"])], automountServiceAccountToken=False)
        request["metadata"]["labels"] = {"registry-source": source}
        lab.create(request)
    for name in (REGISTRY, *CLIENTS.values()):
        ready(lab, name)

    addresses = {
        "service": REGISTRY + ".saf-test.svc",
        "pod": lab.kubectl("get", "pod", REGISTRY, "-o", "jsonpath={.status.podIP}").stdout.strip(),
    }
    if not addresses["pod"]:
        lab.block("The owned registry Pod did not receive an IP")
    deadline = time.monotonic() + 15
    while hit(lab, CLIENTS["trusted"], addresses["service"]) != REACHABLE:
        if time.monotonic() >= deadline:
            lab.block("The real registry returned no ready response through its Service")
        time.sleep(0.3)

    def paths(source):
        return {route: hit(lab, CLIENTS[source], address) for route, address in addresses.items()}

    before = {source: paths(source) for source in CLIENTS}
    lab.check("red", "Before the policy both sources reach both real registry entry paths",
              all(row == REACHABLE for observed in before.values() for row in observed.values()), before)
    expected = {
        "podSelector": {"matchLabels": labels},
        "policyTypes": ["Ingress"],
        "ingress": [{"from": [{"podSelector": {"matchLabels": {"registry-source": "trusted"}}}],
                     "ports": [{"protocol": "TCP", "port": 5000}]}],
    }
    lab.create({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                "metadata": {"name": POLICY}, "spec": expected})
    saved = json.loads(lab.kubectl("get", "networkpolicy", POLICY, "-o", "json").stdout)
    deadline = time.monotonic() + 15
    while True:
        blocked = paths("untrusted")
        if all(item == {"outcome": "timeout"} for item in blocked.values()):
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(0.3)
    green = {"expected_policy_persisted": saved.get("spec") == expected, "registry_paths": blocked}
    lab.check("green", "The unapproved source times out on both registry paths",
              green["expected_policy_persisted"] and all(
                  item == {"outcome": "timeout"} for item in blocked.values()), green)
    approved = paths("trusted")
    lab.check("positive", "The approved source continues to read the native registry API",
              all(item == REACHABLE for item in approved.values()), approved)
    (lab.evidence / "registry-trusted-source.json").write_text(json.dumps({
        "provider": "kindnet", "baseline": before, "blocked": green, "approved": approved,
        "registry_image": REGISTRY_IMAGE,
    }, sort_keys=True, indent=2) + "\n")
