"""Verify a fixed benign policy canary in a real ModSecurity reverse proxy."""
from contextlib import contextmanager
import hashlib
import http.client
import json
from pathlib import Path
import re
import subprocess
import time

SCOPE = (
    "A local Kubernetes v1.36.1 Kind cluster routes owned HTTP traffic through pinned Envoy Gateway, "
    "then the pinned "
    "ModSecurity and OWASP Core Rule Set reverse proxy. The same harmless test header reaches the "
    "owned backend before the canary is installed and is denied after the rule is loaded. "
    "The test checks the specific audit rule ID and continued access for independent permitted "
    "traffic. Deployed ingress attachment, inspection coverage and managed rules need separate evidence."
)
FIXTURES = Path(__file__).with_name("fixtures")
NAMESPACE = "saf-test"
GATEWAY_NAMESPACE = "envoy-gateway-system"
GATEWAY_RELEASE = "v1.10.0"
GATEWAY_CHART_SOURCE = "oci://docker.io/envoyproxy/gateway-helm"
GATEWAY_CHART_SHA256 = "0f72c9050c33dbaab39b865e8cb5ed77f263720b22368eda4ce687077649e659"
GATEWAY_TAG = "v1.10.0@sha256:c2243d43518bed91d3ed8c2db849a4b7a14ac9b96eb019f2ab104bb1ca8572b1"
GATEWAY_IMAGE = f"docker.io/envoyproxy/gateway:{GATEWAY_TAG}"
PROXY_IMAGE = (
    "docker.io/envoyproxy/envoy:distroless-v1.40.2@sha256:"
    "09ca6f2140a61ad8df11779a4a30d52b48433d444466328494f9188c9c35eded"
)
OWNED_PROXY = ("gateway.envoyproxy.io/owning-gateway-namespace=saf-test,"
               "gateway.envoyproxy.io/owning-gateway-name=saf-waf-gateway")
RULE_ID = "10503013"
DENIED_MARKER = "deny-example"
PERMITTED_MARKER = "allowed-after-policy"


@contextmanager
def forward(lab, phase):
    log_path = lab.evidence / f"forward-{phase}.log"
    args = [
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "-n", GATEWAY_NAMESPACE, "port-forward", "--address", "127.0.0.1",
        lab.gateway_proxy_service, ":80",
    ]
    with log_path.open("w") as log:
        process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, env=lab.env)
        try:
            def listener_port():
                if process.poll() is not None:
                    lab.block("Loopback forwarding exited for the owned WAF")
                found = re.search(r"Forwarding from 127\.0\.0\.1:(\d+)", log_path.read_text())
                return int(found.group(1)) if found else None

            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                port = listener_port()
                if port:
                    yield port
                    break
                time.sleep(0.25)
            else:
                lab.block("Timed out waiting for the owned WAF loopback port")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def request(port, marker):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    try:
        connection.request("GET", "/cgi-bin/marker.cgi",
                           headers={"Host": "waf.lab.test", "X-SAF-Lab-Marker": marker, "Connection": "close"})
        response = connection.getresponse()
        return response.status, response.read(4096).decode("utf-8", "replace").strip()
    finally:
        connection.close()


def arrivals(lab):
    result = lab.kubectl("exec", "deployment/saf-marker", "--", "sh", "-c",
                         "if test -f /data/arrivals.log; then cat /data/arrivals.log; fi")
    return result.stdout.splitlines()


def kube_in(lab, namespace, *args, timeout=45):
    return lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                       "--namespace", namespace, f"--request-timeout={timeout - 5}s", *args,
                       timeout=timeout)


def get(lab, namespace, resource, *args):
    result = kube_in(lab, namespace, "get", resource, *args, "-o", "json")
    return json.loads(result.stdout)


def current_conditions(obj, entries, required):
    generation = obj["metadata"]["generation"]
    return any(
        required <= {
            condition["type"] for condition in entry.get("conditions", [])
            if condition["status"] == "True" and condition.get("observedGeneration") == generation
        }
        for entry in entries
    )


def install_gateway(lab):
    work = lab.kubeconfig.parent
    registry = work / "gateway-helm-registry.json"
    lab.command("helm", "pull", GATEWAY_CHART_SOURCE, "--version", GATEWAY_RELEASE,
                "--destination", str(work), "--registry-config", str(registry), timeout=120)
    chart = work / f"gateway-helm-{GATEWAY_RELEASE}.tgz"
    if hashlib.sha256(chart.read_bytes()).hexdigest() != GATEWAY_CHART_SHA256:
        lab.block("Envoy Gateway chart does not match its pinned digest")
    lab.command(
        "helm", "install", "eg", str(chart), "--namespace", GATEWAY_NAMESPACE, "--create-namespace",
        "--kubeconfig", str(lab.kubeconfig), "--kube-context", f"kind-{lab.cluster}",
        "--set-string", "deployment.envoyGateway.image.repository=docker.io/envoyproxy/gateway",
        "--set-string", f"deployment.envoyGateway.image.tag={GATEWAY_TAG}",
        "--set-string", f"config.envoyGateway.provider.kubernetes.shutdownManager.image={GATEWAY_IMAGE}",
        "--wait", "--timeout", "4m", timeout=270,
    )
    lab.apply(FIXTURES / "gateway.yaml")


def audited_rule(lab):
    pattern = r'"ruleId"\s*:\s*"?10503013"?\b|\[id "10503013"\]'
    deadline = time.monotonic() + 20
    while True:
        audit = lab.kubectl("logs", "deployment/saf-waf", "--since=2m").stdout
        matched = [line for line in audit.splitlines()
                   if re.search(pattern, line) and "SAF synthetic fixed-marker canary" in line]
        if matched:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.5)


def run(lab):
    install_gateway(lab)
    for file in ("backend.yaml", "waf-policy-off.yaml", "waf.yaml"):
        lab.apply(FIXTURES / file)
    for deployment in ("saf-marker", "saf-waf"):
        lab.kubectl("rollout", "status", f"deployment/{deployment}", "--timeout=150s", timeout=160)

    kube_in(lab, NAMESPACE, "wait", "--for=condition=Programmed", "gateway/saf-waf-gateway",
            "--timeout=120s", timeout=130)
    route = get(lab, NAMESPACE, "httproute/saf-waf-route")
    if not current_conditions(route, route.get("status", {}).get("parents", []), {"Accepted", "ResolvedRefs"}):
        lab.block("The owned Gateway route was not accepted with resolved backend references")
    services = get(lab, GATEWAY_NAMESPACE, "services", "-l", OWNED_PROXY)["items"]
    pods = get(lab, GATEWAY_NAMESPACE, "pods", "-l", OWNED_PROXY)["items"]
    if len(services) != 1 or len(pods) != 1:
        lab.block("Expected exactly one owned Envoy proxy Service and Pod")
    service, pod = services[0], pods[0]
    lab.gateway_proxy_service = f"service/{service['metadata']['name']}"
    images = sorted(container["image"] for container in pod["spec"]["containers"])
    controller_deployments = [deployment for deployment in get(lab, GATEWAY_NAMESPACE, "deployments")["items"]
                              if deployment["metadata"].get("annotations", {}).get("meta.helm.sh/release-name") == "eg"]
    controller_image_is_pinned = len(controller_deployments) == 1 and any(
        container.get("name") == "envoy-gateway" and container.get("image") == GATEWAY_IMAGE
        for container in controller_deployments[0]["spec"]["template"]["spec"]["containers"]
    )
    rules = route["spec"]["rules"]
    refs = rules[0].get("backendRefs", []) if len(rules) == 1 else []
    backend = refs[0] if len(refs) == 1 else {}
    expected_backend = (
        backend.get("group", "") == "" and backend.get("kind", "Service") == "Service"
        and backend.get("namespace", NAMESPACE) == NAMESPACE
        and backend.get("name") == "saf-waf" and backend.get("port") == 8080
        and backend.get("weight", 1) == 1
    )
    gateway_facts = {
        "route_backend_is_owned_waf": expected_backend,
        "route_accepted_and_resolved": True,
        "gateway_service_cluster_ip": service["spec"]["type"] == "ClusterIP",
        "gateway_controller_image_pinned": controller_image_is_pinned,
        "shutdown_manager_image_pinned": GATEWAY_IMAGE in images,
        "envoy_proxy_image_pinned": PROXY_IMAGE in images,
    }
    lab.check("positive", "The owned Gateway route resolves only to the pinned case WAF",
              all(gateway_facts.values()), gateway_facts)

    with forward(lab, "baseline") as port:
        status, body = request(port, DENIED_MARKER)
    baseline = arrivals(lab)
    lab.check("red", "The exact canary marker reaches the owned backend before activation",
              status == 200 and body == f"backend=owned-marker arrivals=1 marker={DENIED_MARKER}"
              and baseline == [DENIED_MARKER],
              {"http_status": status, "marker_response": body, "backend_arrivals": baseline})

    lab.apply(FIXTURES / "waf-policy-on.yaml")
    lab.kubectl("rollout", "restart", "deployment/saf-waf")
    lab.kubectl("rollout", "status", "deployment/saf-waf", "--timeout=150s", timeout=160)
    with forward(lab, "enforced") as port:
        denied_status, _ = request(port, DENIED_MARKER)
        denied_arrivals = arrivals(lab)
        rule_logged = audited_rule(lab)
        permitted_status, permitted_body = request(port, PERMITTED_MARKER)
    final_arrivals = arrivals(lab)
    evidence = {
        "policy_rule_id": RULE_ID,
        "exact_rule_logged": rule_logged,
        "blocked_http_status": denied_status,
        "permitted_http_status": permitted_status,
        "backend_arrivals_before": baseline,
        "backend_arrivals_after_block": denied_arrivals,
        "backend_arrivals_final": final_arrivals,
    }
    (lab.evidence / "waf-canary-observations.json").write_text(json.dumps(evidence, indent=2) + "\n")
    lab.check("green", "ModSecurity returns HTTP 403 with the exact canary rule and no new backend arrival",
              denied_status == 403 and denied_arrivals == baseline and rule_logged, evidence)
    lab.check("positive", "Independent permitted request returns the marker and is recorded by the backend",
              permitted_status == 200 and permitted_body == f"backend=owned-marker arrivals=2 marker={PERMITTED_MARKER}"
              and final_arrivals == [DENIED_MARKER, PERMITTED_MARKER],
              {"http_status": permitted_status, "marker_response": permitted_body,
               "backend_arrivals": final_arrivals})
