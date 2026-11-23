"""Measure live service-path retirement and retained approved dependencies."""

import json
import time

SCOPE = "Real Kubernetes Services expose harmless marker routes. Retiring one Service backend leaves the approved route available."
NAME = "fixture-routing"
LEGACY = "fixture-legacy-route"
CURRENT = "fixture-current-route"
PORT = 18080
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
SERVER = """
import socketserver
class Marker(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b'owned-public-marker')
socketserver.TCPServer(('0.0.0.0', 18080), Marker).serve_forever()
"""
PROBE = """
import errno, socket, sys
try:
    with socket.create_connection((sys.argv[1], 18080), timeout=1.5) as peer:
        print(peer.recv(128).decode())
except (ConnectionRefusedError, TimeoutError):
    print('route-unavailable')
except OSError as error:
    if error.errno != errno.EHOSTUNREACH:
        raise
    print('route-unavailable')
"""


def pod(name, program):
    container = {"name": "fixture", "image": IMAGE, "command": ["python", "-c", program],
                 "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}},
                 "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                               "limits": {"cpu": "100m", "memory": "64Mi"}}}
    if name == NAME:
        container["readinessProbe"] = {"tcpSocket": {"port": PORT}, "periodSeconds": 1}
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {"app": name}},
            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [container]}}


def backends(lab, service):
    slices = json.loads(lab.kubectl("get", "endpointslices",
                                   "-l", f"kubernetes.io/service-name={service}", "-o", "json").stdout)["items"]
    return sum(len(endpoint["addresses"]) for row in slices for endpoint in (row.get("endpoints") or [])
               if endpoint.get("conditions", {}).get("ready"))


def query(lab, service):
    return lab.kubectl("exec", "pod/fixture-client", "--", "python", "-c", PROBE, service, timeout=8).stdout.strip()


def run(lab):
    marker = "owned-public-marker"
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    lab.create(pod(NAME, SERVER))
    lab.create(pod("fixture-client", "import time; time.sleep(240)"))
    for service in (LEGACY, CURRENT):
        lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": service},
                    "spec": {"selector": {"app": NAME}, "ports": [{"port": PORT, "targetPort": PORT}]}})
    lab.kubectl("wait", "--for=condition=Ready", "pods", "--all", "--timeout=60s", timeout=70)
    for service in (LEGACY, CURRENT):
        deadline = time.monotonic() + 15
        while not backends(lab, service) and time.monotonic() < deadline:
            time.sleep(0.3)
    baseline = {service: query(lab, service) for service in (LEGACY, CURRENT)}
    lab.check("red", "Both owned marker routes are reachable before the scoped restriction",
              all(value == marker for value in baseline.values()),
              {service: value == marker for service, value in baseline.items()})

    patch = '{"spec":{"selector":{"app":"fixture-route-disabled"}}}'
    lab.kubectl("patch", "service", LEGACY, "--type=merge", "-p", patch)
    deadline = time.monotonic() + 20
    retired = False
    while time.monotonic() < deadline:
        if backends(lab, LEGACY) == 0 and query(lab, LEGACY) == "route-unavailable":
            retired = True
            break
        time.sleep(0.3)
    lab.check("green", "The restricted route loses its usable EndpointSlice addresses and refuses new connections",
              retired, {"retired_route_unavailable": retired})
    still_available = backends(lab, CURRENT) == 1 and query(lab, CURRENT) == marker
    lab.check("positive", "The separately approved route still reaches its known backend",
              still_available, {"approved_route_available": still_available})
    (lab.evidence / "metadata-endpoint-observations.json").write_text(json.dumps({
        "legacy_route_available_at_baseline": baseline[LEGACY] == marker,
        "current_route_available_at_baseline": baseline[CURRENT] == marker,
        "legacy_route_retired": retired, "current_route_retained": still_available,
        "provider_endpoint_contacted": False,
    }, indent=2) + "\n")
