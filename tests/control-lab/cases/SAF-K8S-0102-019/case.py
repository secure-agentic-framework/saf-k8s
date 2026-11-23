"""Verify separate client and peer ingress policies for inert endpoint markers."""

import json
import time

SCOPE = "Real Kind Pod networking for two modeled etcd listener classes using only public marker endpoints."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
LABEL = "fixture.example/etcd-role"
SERVER = "fixture-endpoint-markers"
PORTS = {"client": 12379, "peer": 12380}
PROBES = {"api-client": "fixture-api-client", "member": "fixture-peer-member", "ordinary": "fixture-ordinary"}
LISTENER = """
from socketserver import BaseRequestHandler, TCPServer
import threading
class Handler(BaseRequestHandler):
    def handle(self):
        self.request.sendall(self.server.marker)
def serve(port, marker):
    with TCPServer(('0.0.0.0', port), Handler) as server:
        server.marker = marker
        server.serve_forever()
threading.Thread(target=serve, args=(12379, b'client-marker'), daemon=True).start()
serve(12380, b'peer-marker')
"""
CONNECT = """
import socket
import sys
try:
    with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=1.0) as channel:
        print(channel.recv(40).decode())
except TimeoutError:
    print('timed-out')
"""


def start(lab, name, role, program):
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {LABEL: role}},
                "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never",
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                         "containers": [{"name": "unit", "image": IMAGE, "command": ["python", "-c", program],
                                         "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                             "capabilities": {"drop": ["ALL"]}},
                                         "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                                                       "limits": {"cpu": "100m", "memory": "48Mi"}}}]}})


def sample(lab, address, role, port):
    result = lab.kubectl("exec", "pod/" + PROBES[role], "--", "python", "-c", CONNECT, address, str(PORTS[port]))
    return result.stdout.strip()


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet", "--timeout=70s", timeout=80)
    start(lab, SERVER, "listener", LISTENER)
    for role, name in PROBES.items():
        start(lab, name, role, "import time; time.sleep(180)")
    lab.kubectl("wait", "--for=condition=Ready", "pod", "--all", "--timeout=75s", timeout=85)
    endpoint = json.loads(lab.kubectl("get", "pod", SERVER, "-o", "json").stdout)["status"]["podIP"]
    baseline = {listener: sample(lab, endpoint, "ordinary", listener) for listener in PORTS}
    lab.check("red", "Both inert listeners are reachable from the ordinary Pod before ingress policy",
              baseline == {"client": "client-marker", "peer": "peer-marker"}, baseline)
    routes = {"client": "api-client", "peer": "member"}
    lab.create({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": SERVER},
                "spec": {"podSelector": {"matchLabels": {LABEL: "listener"}}, "policyTypes": ["Ingress"],
                         "ingress": [{"from": [{"podSelector": {"matchLabels": {LABEL: role}}}],
                                      "ports": [{"protocol": "TCP", "port": PORTS[listener]}]}
                                     for listener, role in routes.items()]}})
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if sample(lab, endpoint, "ordinary", "client") == "timed-out":
            break
        time.sleep(0.4)
    else:
        lab.block("No enforced ingress timeout was observed in the fixture CNI")
    denied = {"ordinary_peer": sample(lab, endpoint, "ordinary", "peer"),
              "client_on_peer": sample(lab, endpoint, "api-client", "peer"),
              "peer_on_client": sample(lab, endpoint, "member", "client")}
    lab.check("green", "Workload ingress and unintended cross-class paths are denied",
              set(denied.values()) == {"timed-out"}, {"ordinary_client": "timed-out", **denied})
    observed = {listener: sample(lab, endpoint, role, listener) for listener, role in routes.items()}
    lab.check("positive", "The approved client and member each retain their intended connectivity",
              observed == baseline, observed)
    (lab.evidence / "etcd-endpoint-isolation-observations.json").write_text(json.dumps({
        "approved_routes": observed, "other_probes": denied, "cni": "kindnet", "actual_etcd_listener_tested": False,
    }, indent=2) + "\n")
