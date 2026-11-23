"""Exercise ordinary Pod IP segmentation while keeping hardware fabric outside the fixture."""

import json
import time

SCOPE = "Actual Kubernetes CNI ingress policy for three owned TCP endpoints; no InfiniBand, RoCE or hardware is used."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
SERVICE = "fixture-ip-listener"
APPROVED = "fixture-approved-peer"
OTHER = "fixture-other-peer"
PORT = 8080
MARKER = "fabric-ip-fixture-marker"
SERVER = """from http.server import BaseHTTPRequestHandler, HTTPServer
class Fixture(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'fabric-ip-fixture-marker')
HTTPServer(('0.0.0.0', 8080), Fixture).serve_forever()
"""
CLIENT = """import http.client, sys
try:
    connection = http.client.HTTPConnection(sys.argv[1], 8080, timeout=2)
    connection.request('GET', '/')
    reply = connection.getresponse()
    print(reply.read().decode() if reply.status == 200 else 'unexpected-status')
except TimeoutError:
    print('timeout')
except OSError:
    print('network-error')
"""


def pod(name, *, server=False):
    container = {"name": "fixture", "image": IMAGE, "command": ["python", "-c", SERVER if server else "import time; time.sleep(175)"],
                 "resources": {"requests": {"cpu": "5m", "memory": "12Mi"}, "limits": {"cpu": "100m", "memory": "40Mi"}},
                 "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}}}
    if server:
        container["readinessProbe"] = {"httpGet": {"path": "/", "port": PORT}, "periodSeconds": 1}
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {"app": name}},
            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [container]}}


def fetch(lab, source, address):
    result = lab.kubectl("exec", source, "--", "python", "-c", CLIENT, address)
    return result.stdout.strip()


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    for name in (SERVICE, APPROVED, OTHER):
        lab.create(pod(name, server=name == SERVICE))
    for name in (SERVICE, APPROVED, OTHER):
        lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=60s", timeout=70)
    address = json.loads(lab.kubectl("get", "pod", SERVICE, "-o", "json").stdout)["status"]["podIP"]
    initial = {client: fetch(lab, client, address) == MARKER for client in (APPROVED, OTHER)}
    lab.check("red", "Both owned peers can reach the same ordinary TCP listener before isolation",
              all(initial.values()), initial)

    lab.create({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": "fixture-ip-boundary"},
                "spec": {"podSelector": {"matchLabels": {"app": SERVICE}}, "policyTypes": ["Ingress"],
                         "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": APPROVED}}}],
                                      "ports": [{"protocol": "TCP", "port": PORT}]}]}})
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if fetch(lab, OTHER, address) == "timeout":
            break
        time.sleep(0.4)
    else:
        lab.block("The CNI did not establish the observed fixture ingress boundary")
    lab.check("green", "The CNI blocks the outside peer, which previously reached this listener",
              True, {"unapproved_ip_path_blocked": True})
    remaining = fetch(lab, APPROVED, address) == MARKER
    lab.check("positive", "The allowed peer receives the exact marker from the live listener",
              remaining, {"approved_ip_path_works": remaining})
    (lab.evidence / "ip-segmentation-observations.json").write_text(json.dumps({
        "pre_policy_marker_reachable": initial, "unapproved_ip_path_blocked": True,
        "approved_ip_path_works": remaining, "hardware_fabric_tested": False}, indent=2) + "\n")
