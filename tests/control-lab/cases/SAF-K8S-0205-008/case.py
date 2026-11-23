"""Verify a declared kube-proxy mode with its actual kernel state and Service behavior."""

import json
import re
import time

SCOPE = "One fresh Linux Kind node with explicit nftables kube-proxy and two owned IPv4 ClusterIP backends."
SERVICE = "fixture-proxy"
PORT = 18082
CLIENT = "fixture-proxy-client"
ROLE = "fixture.example/proxy"
MODE = "nftables"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
SERVER = """
import socketserver, sys
class Fixture(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(sys.argv[1].encode())
socketserver.TCPServer(('0.0.0.0', 18082), Fixture).serve_forever()
"""
PROBE = """
import errno, socket, sys
try:
    with socket.create_connection((sys.argv[1], 18082), timeout=1.5) as peer:
        print(peer.recv(128).decode())
except (ConnectionRefusedError, ConnectionResetError, TimeoutError):
    print('no-endpoint')
except OSError as error:
    if error.errno not in (errno.EHOSTUNREACH, errno.ENETUNREACH):
        raise
    print('no-endpoint')
"""


def workload(lab, name, role, *argv):
    unit = {"name": "fixture", "image": IMAGE, "command": ["python", *argv],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "5m", "memory": "16Mi"},
                          "limits": {"cpu": "100m", "memory": "64Mi"}}}
    if role != "client":
        unit["readinessProbe"] = {"tcpSocket": {"port": PORT}, "periodSeconds": 1}
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {ROLE: role}},
                "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                             "seccompProfile": {"type": "RuntimeDefault"}},
                         "containers": [unit]}})
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=65s", timeout=75)


def probe(lab, address):
    return lab.kubectl("exec", "pod/" + CLIENT, "--", "python", "-c", PROBE, address, timeout=8).stdout.strip()


def eventually(lab, address, expected):
    result = probe(lab, address)
    deadline = time.monotonic() + 20
    while result != expected and time.monotonic() < deadline:
        time.sleep(0.4)
        result = probe(lab, address)
    return result


def search_concat(value, expected):
    if isinstance(value, dict):
        items = value.get("concat")
        return (isinstance(items, list) and list(map(str, items)) == expected
                or any(search_concat(child, expected) for child in value.values()))
    return isinstance(value, list) and any(search_concat(child, expected) for child in value)


def service_rule(lab, node, address):
    output = lab.command("docker", "exec", node, "nft", "-j", "list", "map", "ip", "kube-proxy", "service-ips",
                         allow_failure=True)
    return output.returncode == 0 and search_concat(json.loads(output.stdout), [address, "tcp", str(PORT)])


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    lab.kubectl("-n", "kube-system", "rollout", "status", "ds/kube-proxy", "--timeout=65s", timeout=75)
    config = json.loads(lab.kubectl("-n", "kube-system", "get", "configmap", "kube-proxy", "-o", "json").stdout)
    configured = re.search(r'(?m)^mode:\s*["\']?([a-z]+)', config["data"]["config.conf"])
    configured = configured.group(1) if configured else None
    runtime = lab.kubectl("-n", "kube-system", "logs", "ds/kube-proxy").stdout
    reports_mode = bool(re.search(r"(?i)using nftables proxier", runtime))
    node, = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    name = node["metadata"]["name"]
    if name != lab.cluster + "-control-plane":
        lab.block("The nftables observation needs the owned Kind node")

    workload(lab, CLIENT, "client", "-c", "import time; time.sleep(160)")
    service = lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": SERVICE},
                          "spec": {"selector": {ROLE: "blue"}, "ports": [{"port": PORT, "targetPort": PORT}]}})
    vip = service["spec"]["clusterIP"]
    without_endpoint = eventually(lab, vip, "no-endpoint") == "no-endpoint"
    mismatch = configured is not None and configured != "iptables" and reports_mode
    lab.check("red", "The running backend fails a conflicting iptables declaration and an empty Service cannot return a marker",
              mismatch and without_endpoint, {"conflicting_mode_detected": mismatch, "empty_service_unavailable": without_endpoint})
    workload(lab, "fixture-blue", "blue", "-c", SERVER, "owned-blue")
    selected = eventually(lab, vip, "owned-blue") == "owned-blue"
    installed = service_rule(lab, name, vip)
    lab.check("green", "Configured and observed nftables mode programs the exact ClusterIP tuple and reaches its selected endpoint",
              configured == MODE and reports_mode and installed and selected,
              {"effective_nftables": configured == MODE and reports_mode,
               "programmed_service_tuple": installed, "owned_endpoint_reachable": selected})
    workload(lab, "fixture-green", "green", "-c", SERVER, "owned-green")
    lab.kubectl("patch", "service", SERVICE, "--type=merge", "-p", json.dumps({"spec": {"selector": {ROLE: "green"}}}))
    changed = eventually(lab, vip, "owned-green") == "owned-green"
    remains = service_rule(lab, name, vip)
    lab.check("positive", "The same programmed ClusterIP follows an approved endpoint change and returns the replacement marker",
              changed and remains, {"changed_endpoint_reachable": changed, "service_stays_programmed": remains})
    (lab.evidence / "proxy-mode-observations.json").write_text(json.dumps({
        "declared_mode": MODE, "configured_mode": configured, "runtime_mode_logged": reports_mode,
        "node_kernel": node["status"]["nodeInfo"]["kernelVersion"], "cluster_ip_tuple_observed": installed,
        "empty_service_unavailable": without_endpoint, "approved_endpoint_initial": selected,
        "approved_endpoint_changed": changed, "service_tuple_retained": remains,
    }, indent=2) + "\n")
