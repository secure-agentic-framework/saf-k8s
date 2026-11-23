"""Verify source-class egress boundaries using two owned inert services."""

import json
import time

SCOPE = "Actual Kind egress and restricted admission over synthetic metadata and approved identity marker Pods."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
KEY = "fixture.example/path"
CLIENT = "fixture-governed-workload"
METADATA = "fixture-node-marker"
IDENTITY = "fixture-identity-marker"
PORT = 18080
SERVER = """
import socketserver, sys
class Marker(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(sys.argv[1].encode())
socketserver.TCPServer(('0.0.0.0', 18080), Marker).serve_forever()
"""
PROBE = """
import socket, sys
try:
    with socket.create_connection((sys.argv[1], 18080), timeout=1.5) as peer:
        print(peer.recv(128).decode())
except TimeoutError:
    print('timeout')
"""


def pod(name, role, argv, *, host=False):
    spec = {"automountServiceAccountToken": False, "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "marker", "image": IMAGE, "command": ["python", *argv],
                            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                "capabilities": {"drop": ["ALL"]}},
                            "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                                          "limits": {"cpu": "100m", "memory": "48Mi"}}}]}
    if host:
        spec["hostNetwork"] = True
    if role != "client":
        spec["containers"][0]["readinessProbe"] = {"tcpSocket": {"port": PORT}, "periodSeconds": 1}
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {KEY: role}}, "spec": spec}


def address(lab, name):
    return json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)["status"]["podIP"]


def received(lab, destination):
    return lab.kubectl("exec", "pod/" + CLIENT, "--", "python", "-c", PROBE, destination).stdout.strip()


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet", "--timeout=65s", timeout=75)
    lab.create(pod(CLIENT, "client", ["-c", "import time; time.sleep(180)"]))
    lab.create(pod(METADATA, "node-metadata", ["-c", SERVER, METADATA]))
    lab.create(pod(IDENTITY, "approved-identity", ["-c", SERVER, IDENTITY]))
    lab.kubectl("wait", "--for=condition=Ready", "pods", "--all", "--timeout=70s", timeout=80)
    owned = {name: address(lab, name) for name in (METADATA, IDENTITY)}
    baseline = {name: received(lab, owned[name]) for name in owned}
    lab.check("red", "Before the egress policy, the governed Pod reaches both inert marker paths",
              baseline == {name: name for name in owned}, baseline)

    lab.create({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                "metadata": {"name": "fixture-governed-paths"}, "spec": {
                    "podSelector": {"matchLabels": {KEY: "client"}}, "policyTypes": ["Egress"],
                    "egress": [{"to": [{"podSelector": {"matchLabels": {KEY: "approved-identity"}}}],
                                "ports": [{"protocol": "TCP", "port": PORT}]}],
                }})
    deadline = time.monotonic() + 20
    blocked = False
    while time.monotonic() < deadline:
        blocked = received(lab, owned[METADATA]) == "timeout"
        if blocked:
            break
        time.sleep(0.4)
    host_request = lab.create(pod("fixture-host-declaration", "client", ["-c", "print('public')"], host=True),
                              dry_run=True, allow_failure=True)
    host_denied = host_request.returncode != 0 and "violates PodSecurity" in host_request.stderr and "hostNetwork" in host_request.stderr
    lab.check("green", "Actual egress denies the node metadata marker and admission rejects a governed host-network declaration",
              blocked and host_denied, {"inert_node_path_denied": blocked, "host_network_declaration_rejected": host_denied})

    approved = received(lab, owned[IDENTITY]) == IDENTITY and received(lab, owned[METADATA]) == "timeout"
    lab.check("positive", "The allowed identity fixture remains reachable while the unapproved path stays denied",
              approved, {"approved_identity_path_reachable": approved})
    (lab.evidence / "metadata-path-observations.json").write_text(json.dumps({
        "unapproved_path_denied": blocked, "host_network_declaration_rejected": host_denied,
        "approved_path_reachable": approved, "provider_or_node_metadata_contacted": False,
    }, indent=2) + "\n")
