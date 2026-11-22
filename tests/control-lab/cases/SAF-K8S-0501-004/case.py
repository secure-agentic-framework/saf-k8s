"""Exercise Cilium HTTP method policy between case-owned synthetic Pods."""
from hashlib import sha256
import json
from pathlib import Path
import time


CONTROL_ID = "SAF-K8S-0501-004"
CILIUM_VERSION = "1.20.5"
CILIUM_CHART_SHA256 = "0c7592eb75179ecf46dd3ec22145916f0164c4401214ea15afb5b230b1d11a21"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-0501-004"
CLIENT = "owned-http-client"
SERVER = "owned-http-server"
PORT = 8080
MARKER = "saf-0501-004-owned-harmless-response-6f83"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
SCOPE = (
    "Cilium 1.20.5 L7 ingress policy on kind v0.32.0 / Kubernetes v1.36.1, "
    "IPv4 TCP/8080, one case-owned client Pod and one case-owned HTTP server Pod, "
    "direct Pod-IP requests to /safe. The scope is method matching. DNS, Service "
    "routing, external/public traffic, other "
    "protocols, production policy, Calico, or cluster-wide policy is exercised."
)

SERVER_CODE = r'''from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def respond(self):
        body = b"''' + MARKER.encode().decode() + r'''"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_GET = respond
    do_POST = respond
    def log_message(self, fmt, *args):
        pass
HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''

PROBE_CODE = r'''import json, sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
url, method = sys.argv[1], sys.argv[2]
try:
    with urlopen(Request(url, method=method), timeout=4) as response:
        print(json.dumps({"status": response.status,
                          "body": response.read().decode("utf-8", "replace")}))
except HTTPError as error:
    print(json.dumps({"status": error.code,
                      "body": error.read().decode("utf-8", "replace")}))
except URLError as error:
    print(json.dumps({"status": None, "error": str(error.reason)}))
'''


def wait_pod(lab, name):
    lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=120s", timeout=130)
    pod_data = json.loads(lab.kubectl(
        "-n", NAMESPACE, "get", f"pod/{name}", "-o", "json").stdout)
    pod_ip = pod_data.get("status", {}).get("podIP")
    if not pod_ip:
        lab.block(f"Owned Pod {name} has no Pod IP")
    return pod_ip


def install_cilium(lab):
    kind_version = lab.command("kind", "version").stdout.strip()
    if not kind_version.startswith("kind v0.32.0"):
        lab.block(f"Expected pinned kind v0.32.0, got {kind_version}")
    server_version = json.loads(lab.kubectl("version", "-o", "json").stdout)[
        "serverVersion"]["gitVersion"]
    if server_version != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, got {server_version}")

    # kindnet remains active until the cluster and shared runner are Ready.
    # Helm then installs the pinned full Cilium CNI. cni.exclusive moves the
    # previous CNI config aside; only Pods created afterward are in this test.
    config_dir = lab.kubeconfig.parent
    registry = config_dir / "helm-registry.json"
    lab.command("helm", "pull", "oci://quay.io/cilium/charts/cilium",
                "--version", CILIUM_VERSION, "--destination", str(config_dir),
                "--registry-config", str(registry), timeout=120)
    chart = config_dir / f"cilium-{CILIUM_VERSION}.tgz"
    if sha256(chart.read_bytes()).hexdigest() != CILIUM_CHART_SHA256:
        lab.block("The pinned Cilium chart archive did not match the expected digest")
    lab.command(
        "helm", "upgrade", "--install", "cilium", str(chart),
        "--kubeconfig", str(lab.kubeconfig), "--kube-context", f"kind-{lab.cluster}",
        "--namespace", "kube-system", "--registry-config", str(registry),
        "--values", str(Path(__file__).with_name("cilium-values.yaml")),
        "--wait", "--timeout", "5m", timeout=320,
    )
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/cilium",
                "--timeout=240s", timeout=250)
    lab.kubectl("-n", "kube-system", "rollout", "status", "deployment/cilium-operator",
                "--timeout=240s", timeout=250)
    agent_data = json.loads(lab.kubectl(
        "-n", "kube-system", "get", "daemonset/cilium", "-o", "json").stdout)
    agent_images = [container["image"] for container in
                    agent_data["spec"]["template"]["spec"]["containers"]]
    if not any(f"cilium:v{CILIUM_VERSION}" in image for image in agent_images):
        lab.block(f"Cilium image is not pinned to v{CILIUM_VERSION}: {agent_images}")
    lab.kubectl("wait", "--for=condition=Ready", "nodes", "--all", "--timeout=120s",
                timeout=130)
    lab.check("positive", "Pinned Cilium CNI agents and operator are ready",
              True, {"kind": kind_version, "kubernetes": server_version,
                     "cilium_chart": CILIUM_VERSION, "agent_images": agent_images,
                     "node_readiness": "all Ready after Cilium install"})


def make_pod(name, labels, command, *, port=None):
    container = {
        "name": "synthetic-http",
        "image": PYTHON_IMAGE,
        "imagePullPolicy": "IfNotPresent",
        "command": ["python", "-u", "-c", command],
        "securityContext": {"allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                            "runAsNonRoot": True, "runAsUser": 65532},
        "resources": {"requests": {"cpu": "10m", "memory": "64Mi"},
                      "limits": {"cpu": "250m", "memory": "128Mi"}},
    }
    if port:
        container["ports"] = [{"name": "http", "containerPort": port,
                                "protocol": "TCP"}]
        container["readinessProbe"] = {
            "tcpSocket": {"port": port}, "initialDelaySeconds": 1,
            "periodSeconds": 1, "failureThreshold": 20,
        }
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": NAMESPACE, "labels": labels},
            "spec": {"automountServiceAccountToken": False,
                     "restartPolicy": "Always", "containers": [container]}}


def observe(lab, ip, method):
    result = lab.kubectl(
        "-n", NAMESPACE, "exec", f"pod/{CLIENT}", "--", "python", "-c",
        PROBE_CODE, f"http://{ip}:{PORT}/safe", method, timeout=15,
    )
    try:
        return json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        lab.block("Synthetic HTTP probe did not return its structured response")


def expect(lab, phase, claim, ip, method, status, body=None):
    deadline = time.monotonic() + 30
    actual = None
    while time.monotonic() < deadline:
        actual = observe(lab, ip, method)
        if actual.get("status") == status and (body is None or actual.get("body") == body):
            break
        time.sleep(0.5)
    lab.check(phase, claim,
              actual is not None and actual.get("status") == status
              and (body is None or actual.get("body") == body),
              {"method": method, "path": "/safe", "expected_status": status,
               "expected_marker": body, "observed": actual})


def run(lab):
    install_cilium(lab)
    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl("-n", NAMESPACE, "apply", "-f", "-", payload=json.dumps(make_pod(
        SERVER, {"app": SERVER}, SERVER_CODE, port=PORT)))
    lab.kubectl("-n", NAMESPACE, "apply", "-f", "-", payload=json.dumps(make_pod(
        CLIENT, {"app": CLIENT}, "import time; time.sleep(3600)")))
    server_ip = wait_pod(lab, SERVER)
    wait_pod(lab, CLIENT)

    # Both methods must reach the same owned listener before enforcement.
    expect(lab, "red", "Without Cilium policy, owned server returns its marker to GET",
           server_ip, "GET", 200, MARKER)
    expect(lab, "red", "Without Cilium policy, owned server returns its marker to POST",
           server_ip, "POST", 200, MARKER)

    lab.kubectl("-n", NAMESPACE, "apply", "-f",
                str(Path(__file__).with_name("http-method-policy.yaml")))
    expect(lab, "positive", "Cilium allows the explicitly permitted GET /safe",
           server_ip, "GET", 200, MARKER)
    expect(lab, "green", "Cilium L7 policy rejects POST /safe with HTTP 403",
           server_ip, "POST", 403)
