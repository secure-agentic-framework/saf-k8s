"""Verify a bounded route rate limit in the harness-owned Kubernetes cluster."""
from contextlib import contextmanager
import hashlib
import http.client
import json
from pathlib import Path
import re
import subprocess
import time

SCOPE = (
    "An owned Kind Kubernetes v1.36.1 cluster with Envoy Gateway v1.10.0. A single local "
    "proxy replica throttles one fixture HTTPRoute at three requests per minute. Four "
    "sequential marker requests before and after policy prove the threshold and backend "
    "arrivals. An unrelated route stays available. Production WAF, client-key governance, "
    "backend capacity, and shared limits across replicas need separate evidence."
)
FIXTURES = Path(__file__).with_name("fixtures")
NAMESPACE = "envoy-gateway-system"
RELEASE = "v1.10.0"
CHART_SOURCE = "oci://docker.io/envoyproxy/gateway-helm"
CHART_SHA256 = "0f72c9050c33dbaab39b865e8cb5ed77f263720b22368eda4ce687077649e659"
GATEWAY_TAG = "v1.10.0@sha256:c2243d43518bed91d3ed8c2db849a4b7a14ac9b96eb019f2ab104bb1ca8572b1"
GATEWAY_IMAGE = f"docker.io/envoyproxy/gateway:{GATEWAY_TAG}"
PROXY_IMAGE = (
    "docker.io/envoyproxy/envoy:distroless-v1.40.2@sha256:"
    "09ca6f2140a61ad8df11779a4a30d52b48433d444466328494f9188c9c35eded"
)
OWNED_PROXY = ("gateway.envoyproxy.io/owning-gateway-namespace=saf-test,"
               "gateway.envoyproxy.io/owning-gateway-name=eg")
LIMIT = 3


def kube(lab, namespace, *args, timeout=50):
    return lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                       "--namespace", namespace, *args, timeout=timeout).stdout


def get(lab, namespace, resource, *args):
    return json.loads(kube(lab, namespace, "get", resource, *args, "-o", "json"))


def install(lab):
    work = lab.kubeconfig.parent
    registry = work / "helm-registry.json"
    lab.command("helm", "pull", CHART_SOURCE, "--version", RELEASE, "--destination", str(work),
                "--registry-config", str(registry), timeout=120)
    chart = work / f"gateway-helm-{RELEASE}.tgz"
    if hashlib.sha256(chart.read_bytes()).hexdigest() != CHART_SHA256:
        lab.block("Envoy Gateway chart does not match its pinned digest")
    lab.command(
        "helm", "install", "eg", str(chart), "--namespace", NAMESPACE, "--create-namespace",
        "--kubeconfig", str(lab.kubeconfig), "--kube-context", f"kind-{lab.cluster}",
        "--set-string", "deployment.envoyGateway.image.repository=docker.io/envoyproxy/gateway",
        "--set-string", f"deployment.envoyGateway.image.tag={GATEWAY_TAG}",
        "--set-string", f"config.envoyGateway.provider.kubernetes.shutdownManager.image={GATEWAY_IMAGE}",
        "--wait", "--timeout", "4m", timeout=270,
    )
    for file in ("workloads.yaml", "gateway.yaml"):
        lab.apply(FIXTURES / file)
    for workload in ("protected-backend", "unrelated-backend"):
        lab.kubectl("rollout", "status", f"deployment/{workload}", "--timeout=95s", timeout=105)
    lab.kubectl("wait", "--for=condition=Programmed", "gateway/eg", "--timeout=120s", timeout=130)


def has_current_conditions(obj, entries, required):
    generation = obj["metadata"]["generation"]
    return any(
        required <= {
            condition["type"] for condition in entry.get("conditions", [])
            if condition["status"] == "True" and condition.get("observedGeneration") == generation
        }
        for entry in entries
    )


def wait(lab, label, read, timeout=60):
    deadline = time.monotonic() + timeout
    while True:
        value = read()
        if value:
            return value
        if time.monotonic() >= deadline:
            lab.block(f"Timed out waiting for {label}")
        time.sleep(0.5)


def wait_routes(lab):
    for name in ("protected", "unrelated"):
        def route_ready():
            route = get(lab, "saf-test", f"httproute/{name}")
            return has_current_conditions(route, route.get("status", {}).get("parents", []),
                                          {"Accepted", "ResolvedRefs"})

        wait(lab, f"route {name} acceptance and resolved references", route_ready)


@contextmanager
def forward(lab, resource, remote_port):
    log_path = lab.evidence / f"forward-{remote_port}.log"
    args = [
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "-n", NAMESPACE, "port-forward", "--address", "127.0.0.1", resource, f":{remote_port}",
    ]
    with log_path.open("w") as log:
        process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, env=lab.env)
        try:
            def listener_port():
                if process.poll() is not None:
                    lab.block(f"Loopback forwarding exited for owned resource {resource}")
                found = re.search(r"Forwarding from 127\.0\.0\.1:(\d+)", log_path.read_text())
                return int(found.group(1)) if found else None

            yield wait(lab, f"loopback forwarding for {resource}", listener_port)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def request(port, host, path="/green", max_bytes=4096):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=4)
    try:
        connection.request("GET", path, headers={"Host": host, "Connection": "close"})
        response = connection.getresponse()
        return response.status, response.read(max_bytes).decode(), response.getheader("Retry-After")
    finally:
        connection.close()


def protected(port):
    return [request(port, "protected.lab.test") for _ in range(LIMIT + 1)]


def arrivals(lab, workload):
    output = kube(lab, "saf-test", "logs", f"deployment/{workload}")
    return sum('"GET /green HTTP/' in line for line in output.splitlines())


def active_route_limit(port):
    status, snapshot, _ = request(port, "localhost", "/config_dump?resource=dynamic_route_configs", 1024 * 1024)
    if status != 200:
        return False
    for dynamic in json.loads(snapshot).get("configs", []):
        route_config = dynamic.get("route_config", {})
        for host in route_config.get("virtual_hosts", []):
            if "protected.lab.test" not in host.get("domains", []):
                continue
            for route in host.get("routes", []):
                filters = route.get("typed_per_filter_config", {})
                config = filters.get("envoy.filters.http.local_ratelimit", {})
                bucket = config.get("token_bucket", {})
                if bucket.get("max_tokens") == LIMIT and bucket.get("tokens_per_fill") == LIMIT:
                    return True
    return False


def run(lab):
    install(lab)
    wait_routes(lab)

    services = get(lab, NAMESPACE, "services", "-l", OWNED_PROXY)["items"]
    pods = get(lab, NAMESPACE, "pods", "-l", OWNED_PROXY)["items"]
    if len(services) != 1 or len(pods) != 1:
        lab.block("Expected exactly one owned Envoy proxy Service and Pod")
    service, pod = services[0], pods[0]
    images = sorted(container["image"] for container in pod["spec"]["containers"])
    proxy_facts = {
        "cluster_ip_only": service["spec"]["type"] == "ClusterIP",
        "proxy_image_pinned": PROXY_IMAGE in images,
        "shutdown_manager_image_pinned": GATEWAY_IMAGE in images,
        "proxy_count": len(pods),
    }
    lab.check("positive", "One pinned proxy serves the case-owned internal Gateway",
              all(proxy_facts.values()), proxy_facts)
    with forward(lab, f"service/{service['metadata']['name']}", 80) as http_port:
        baseline = protected(http_port)
        baseline_status = [item[0] for item in baseline]
        baseline_markers = all(item[1] == "PROTECTED_GREEN\n" for item in baseline)
        baseline_arrivals = arrivals(lab, "protected-backend")
        lab.check("red", "All four protected requests reach the backend before throttling",
                  baseline_status == [200] * (LIMIT + 1) and baseline_markers and baseline_arrivals == LIMIT + 1,
                  {"http_statuses": baseline_status, "markers_matched": baseline_markers,
                   "backend_arrivals": baseline_arrivals})
        lab.apply(FIXTURES / "rate-limit.yaml")

        def policy_ready():
            policy = get(lab, "saf-test", "backendtrafficpolicy/protected-route-local-limit")
            return has_current_conditions(policy, policy.get("status", {}).get("ancestors", []), {"Accepted"})

        wait(lab, "current BackendTrafficPolicy acceptance", policy_ready)
        with forward(lab, f"pod/{pod['metadata']['name']}", 19000) as admin_port:
            wait(lab, "active Envoy route token bucket", lambda: active_route_limit(admin_port))

        limited = protected(http_port)
        statuses = [item[0] for item in limited]
        remaining_markers = all(item[1] == "PROTECTED_GREEN\n" for item in limited[:LIMIT])
        retry_after = limited[-1][2]
        unrelated = request(http_port, "unrelated.lab.test")
        unrelated_green = unrelated[0] == 200 and unrelated[1] == "UNRELATED_GREEN\n"
        protected_delta = arrivals(lab, "protected-backend") - baseline_arrivals
        unrelated_arrivals = arrivals(lab, "unrelated-backend")
        observations = {
            "active_limit": LIMIT, "protected_statuses": statuses, "markers_matched": remaining_markers,
            "protected_backend_delta": protected_delta,
            "unrelated_status": unrelated[0], "unrelated_backend_arrivals": unrelated_arrivals,
        }
        (lab.evidence / "rate-limit-observations.json").write_text(
            json.dumps({**observations, "retry_after": retry_after}, indent=2, sort_keys=True) + "\n"
        )
        lab.check("green", "Envoy rejects the fourth protected request and the backend receives only three",
                  statuses == [200] * LIMIT + [429] and protected_delta == LIMIT,
                  observations)
        lab.check("positive", "Permitted protected requests and unrelated route return their markers",
                  remaining_markers and unrelated_green and unrelated_arrivals == 1,
                  {"protected_markers": remaining_markers, "unrelated_marker": unrelated_green,
                   "unrelated_backend_arrivals": unrelated_arrivals})
