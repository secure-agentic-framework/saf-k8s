"""SAF-K8S-0504-008: HTTP operation authorization with Cilium L7 policy."""

import hashlib
import json
from pathlib import Path
import time

SCOPE = (
    "One disposable, single-node Kind cluster with Cilium 1.20.5; one same-namespace "
    "BusyBox marker CGI backend and one pinned Python client. Tests fixed HTTP requests to "
    "the owned ClusterIP service over cleartext HTTP/1.1 on TCP/8080. A namespaced "
    "CiliumNetworkPolicy selects only the marker backend and client. It permits only "
    "GET /cgi-bin/marker with X-Case-Grant exactly equal to 'permit'. Three individual "
    "method, path, and header mismatches are each sent before and after policy; each "
    "must reach the marker before policy and receive HTTP 403 without marker arrival "
    "after policy. A permitted request on the same path must still succeed."
)

CILIUM_CHART = "oci://quay.io/cilium/charts/cilium"
CILIUM_VERSION = "1.20.5"
CILIUM_AGENT = "quay.io/cilium/cilium:v1.20.5@sha256:aa72499f075ad729947ea91b026218aceba24f1a8e4534bf36b8368c7c561526"
CILIUM_OPERATOR_GENERIC = "quay.io/cilium/operator-generic:v1.20.5@sha256:c6e7de6665aa9701db86c4fe46828a75a0d167afe084a9ffb5bce34b2c4fa8c4"
CILIUM_ENVOY = "quay.io/cilium/cilium-envoy:v1.39.6-1794557904-dee711ff0e84b106edd0abcdd71961af1b870359@sha256:bdef13043ebaa7b9dcd8e3a86be41080bb5369e017cd759a12daf89e2b8fafe7"
HERE = Path(__file__).resolve().parent
CHART_SHA = "0c7592eb75179ecf46dd3ec22145916f0164c4401214ea15afb5b230b1d11a21"

REQUESTS = (
    {"id": "method-deny", "method": "POST", "path": "/cgi-bin/marker", "header": "permit", "post": "probe=1"},
    {"id": "path-deny", "method": "GET", "path": "/cgi-bin/marker-alt", "header": "permit"},
    {"id": "header-deny", "method": "GET", "path": "/cgi-bin/marker", "header": "reject"},
)


def _install_cilium(lab):
    work = lab.kubeconfig.parent
    registry = work / "helm-registry.json"
    lab.command("helm", "pull", CILIUM_CHART, "--version", CILIUM_VERSION,
                "--destination", str(work), "--registry-config", str(registry), timeout=100)
    chart = work / f"cilium-{CILIUM_VERSION}.tgz"
    if hashlib.sha256(chart.read_bytes()).hexdigest() != CHART_SHA:
        lab.block("The downloaded Cilium chart differs from the pinned artifact")
    lab.command("helm", "install", "cilium", str(chart),
        "--namespace", "kube-system",
        "--kubeconfig", str(lab.kubeconfig),
        "--kube-context", f"kind-{lab.cluster}",
        "-f", str(HERE / "cilium-values.yaml"),
        "--wait", "--timeout", "4m",
        timeout=260,
    )


def _policy():
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": "marker-http-operation"},
        "spec": {
            "description": "Permit only the fixed marker operation and exact grant header.",
            "endpointSelector": {"matchLabels": {"app": "marker-backend"}},
            "ingress": [{
                "fromEndpoints": [{"matchLabels": {"app": "marker-client"}}],
                "toPorts": [{
                    "ports": [{"port": "8080", "protocol": "TCP"}],
                    "rules": {"http": [{
                        "method": "^GET$",
                        "path": "^/cgi-bin/marker$",
                        "headerMatches": [{"name": "X-Case-Grant", "value": "permit"}],
                    }]},
                }],
            }],
        },
    }


def _node_ready(lab):
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}"]
    for resource in ("daemonset/cilium", "daemonset/cilium-envoy", "deployment/cilium-operator"):
        lab.command(*args, "-n", "kube-system", "rollout", "status", resource,
                    "--timeout=80s", timeout=90)
    state = json.loads(lab.command(*args, "-n", "kube-system", "get", "pods", "-o", "json").stdout)
    ready_images = set()
    for pod in state["items"]:
        ready = {container["name"] for container in pod.get("status", {}).get("containerStatuses", [])
                 if container["ready"]}
        ready_images.update(container["image"] for container in pod["spec"]["containers"]
                            if container["name"] in ready)
    observed = {image.split("@")[0]: image in ready_images
                for image in (CILIUM_AGENT, CILIUM_ENVOY, CILIUM_OPERATOR_GENERIC)}
    lab.check("positive", "The pinned Cilium agent, operator and Envoy are ready",
              all(observed.values()), observed)


def _http(lab, request):
    script = (HERE / "request.py").read_text()
    result = lab.kubectl("exec", "marker-client", "--", "python", "-c", script, json.dumps(request),
                         timeout=14, allow_failure=True)
    return json.loads(result.stdout) if result.returncode == 0 else {"status": 0, "body": ""}


def _arrivals(lab):
    result = lab.kubectl("exec", "marker-backend", "--", "sh", "-c",
                         "if test -f /tmp/case-arrivals; then cat /tmp/case-arrivals; fi")
    return [line.split()[0] for line in result.stdout.splitlines()]


def _wait_for_policy(lab):
    request = {**REQUESTS[-1], "id": "readiness-marker"}
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if _http(lab, request) == {"status": 403, "body": "Access denied"}:
            return
        time.sleep(0.5)
    lab.block("The Cilium L7 readiness marker did not return its expected denial")


def run(lab):
    _install_cilium(lab)
    _node_ready(lab)
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}"]
    lab.command(*args, "-n", "kube-system", "rollout", "restart", "deployment/coredns")
    lab.command(*args, "-n", "kube-system", "rollout", "status", "deployment/coredns",
                "--timeout=80s", timeout=90)
    lab.apply(HERE / "resources.json")
    lab.kubectl("wait", "--for=condition=Ready", "pod/marker-backend", "pod/marker-client",
                "--timeout=100s", timeout=110)
    before = {}
    for request in REQUESTS:
        response = _http(lab, request)
        ids = _arrivals(lab)
        passed = response == {"status": 200, "body": "case marker"} and ids.count(request["id"]) == 1
        before[request["id"]] = passed
        lab.check("red", f"{request['id']} reaches the owned backend before the L7 policy",
                  passed, {"http_status": response["status"], "exact_backend_marker": response["body"] == "case marker"})
    lab.create(_policy())
    _wait_for_policy(lab)
    baseline = [name for name in _arrivals(lab) if name != "readiness-marker"]
    permitted = {"id": "policy-permit", "method": "GET", "path": "/cgi-bin/marker", "header": "permit"}
    allowed = _http(lab, permitted)
    expected = [*baseline, permitted["id"]]
    arrivals = [name for name in _arrivals(lab) if name != "readiness-marker"]
    lab.check("positive", "The explicitly allowed method, path and header still reach the backend",
              allowed == {"status": 200, "body": "case marker"} and arrivals == expected,
              {"http_status": allowed["status"], "expected_arrival": arrivals == expected})
    denied = {}
    for request in REQUESTS:
        response = _http(lab, request)
        arrivals = [name for name in _arrivals(lab) if name != "readiness-marker"]
        unchanged = arrivals == expected
        denied[request["id"]] = {"http_status": response["status"], "backend_unchanged": unchanged,
                                 "exact_proxy_message": response["body"] == "Access denied"}
        lab.check("green", f"{request['id']} receives exact Cilium HTTP 403 before the backend",
                  response == {"status": 403, "body": "Access denied"} and unchanged, denied[request["id"]])
    (lab.evidence / "operation-observations.json").write_text(
        json.dumps({"baseline": before, "denials": denied, "final_backend_arrivals": arrivals}, indent=2) + "\n"
    )
