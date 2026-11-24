"""Measure live service-path retirement and retained approved dependencies."""

import json
import time

SCOPE = "Observe Service retirement and restoration, and the kernel-enforced IPv4 response TTL across a routed owned marker path."
NAME = "fixture-routing"
LEGACY = "fixture-legacy-route"
CURRENT = "fixture-current-route"
PORT = 18080
CLIENT = "fixture-client"
SELECTOR = "saf.example/fixture-node"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
SERVER = """
import socket, socketserver, threading
from pathlib import Path
phase = Path("/run/fixture/hop-limit")
phase.write_text("32")
class Marker(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b'owned-public-marker')
tcp = socketserver.TCPServer(('0.0.0.0', 18080), Marker)
threading.Thread(target=tcp.serve_forever, daemon=True).start()
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
    peer.bind(("0.0.0.0", 18081))
    while True:
        token, source = peer.recvfrom(128)
        hop_limit = int(phase.read_text())
        if hop_limit not in (1, 32):
            raise ValueError("unexpected fixture response hop limit")
        peer.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, hop_limit)
        sent = peer.sendto(b"owned-hop-marker", source)
        print(f"{token.decode()} ttl={peer.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)} bytes={sent}", flush=True)
"""
UDP_PROBE = """
import socket, sys
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
    peer.settimeout(2)
    peer.connect((sys.argv[1], 18081))
    peer.send(sys.argv[2].encode())
    try:
        print(peer.recv(128).decode())
    except TimeoutError:
        print("response-timeout")
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
    origin = name == NAME
    if origin:
        container["volumeMounts"] = [{"name": "fixture", "mountPath": "/run/fixture"}]
        container["readinessProbe"] = {"tcpSocket": {"port": PORT}, "periodSeconds": 1}
    placement = {"nodeSelector": {SELECTOR: "origin" if origin else "peer"}}
    if origin:
        placement["tolerations"] = [{"key": "node-role.kubernetes.io/control-plane", "operator": "Exists",
                                      "effect": "NoSchedule"}]
        placement["volumes"] = [{"name": "fixture", "emptyDir": {}}]
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {"app": name}},
            "spec": {**placement, "restartPolicy": "Never", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [container]}}


def backends(lab, service):
    slices = json.loads(lab.kubectl("get", "endpointslices",
                                   "-l", f"kubernetes.io/service-name={service}", "-o", "json").stdout)["items"]
    return sum(len(endpoint["addresses"]) for row in slices for endpoint in (row.get("endpoints") or [])
               if endpoint.get("conditions", {}).get("ready"))


def query(lab, service):
    return lab.kubectl("exec", "pod/" + CLIENT, "--", "python", "-c", PROBE, service, timeout=8).stdout.strip()


def pod_field(lab, name, field):
    return lab.kubectl("get", "pod", name, "-o", f"jsonpath={{{field}}}").stdout.strip()


def udp(lab, source, destination, token):
    return lab.kubectl("exec", "pod/" + source, "--", "python", "-c", UDP_PROBE, destination, token, timeout=8).stdout.strip()


def fixture_hop_limit(lab, limit):
    program = f"from pathlib import Path; Path('/run/fixture/hop-limit').write_text('{limit}')"
    lab.kubectl("exec", "pod/" + NAME, "--", "python", "-c", program)


def route_lifecycle(lab, marker):
    lab.kubectl("patch", "service", LEGACY, "--type=merge", "-p", '{"spec":{"selector":{"app":"fixture-route-disabled"}}}')
    deadline = time.monotonic() + 20
    retired = False
    while time.monotonic() < deadline:
        if backends(lab, LEGACY) == 0 and query(lab, LEGACY) == "route-unavailable":
            retired = True
            break
        time.sleep(0.3)
    lab.check("green", "The retired Service loses ready EndpointSlice addresses and refuses new connections",
              retired, {"retired_route_unavailable": retired})
    still_available = backends(lab, CURRENT) == 1 and query(lab, CURRENT) == marker
    lab.check("positive", "The independent approved Service retains its backend and successful traffic",
              still_available, {"approved_route_available": still_available})
    restore = json.dumps({"spec": {"selector": {"app": NAME}}})
    lab.kubectl("patch", "service", LEGACY, "--type=merge", "-p", restore)
    deadline = time.monotonic() + 20
    restored = False
    while time.monotonic() < deadline:
        if backends(lab, LEGACY) == 1 and query(lab, LEGACY) == marker:
            restored = True
            break
        time.sleep(0.3)
    lab.check("positive", "Restoring the scoped route makes the original Service reachable again",
              restored, {"retired_route_recovered": restored})
    return {"legacy_route_retired": retired, "current_route_retained": still_available, "legacy_route_restored": restored}


def verify_hop_limit(lab):
    destination = pod_field(lab, NAME, ".status.podIP")
    client_node = pod_field(lab, CLIENT, ".spec.nodeName")
    listener_node = pod_field(lab, NAME, ".spec.nodeName")
    different_nodes = client_node != listener_node
    marker = "owned-hop-marker"
    before = udp(lab, CLIENT, destination, "routed-before")
    lab.check("red", "The cross-node client receives the owned UDP marker with the normal response TTL",
              different_nodes and before == marker, {"distinct_nodes": different_nodes, "normal_response_crosses_path": before == marker})

    fixture_hop_limit(lab, 1)
    routed = udp(lab, CLIENT, destination, "routed-one-hop")
    local = udp(lab, NAME, "127.0.0.1", "local-one-hop")
    responses = set(lab.kubectl("logs", "pod/" + NAME).stdout.splitlines())
    expected_dispatch = f"routed-one-hop ttl=1 bytes={len(marker)}"
    origin_sent = expected_dispatch in responses
    lab.check("green", "The kernel-limited response is sent and received locally, but does not cross the routed path",
              routed == "response-timeout" and local == marker and origin_sent,
              {"routed_response_lost": routed == "response-timeout", "local_reply_retained": local == marker,
               "origin_confirmed_limited_response": origin_sent})

    fixture_hop_limit(lab, 32)
    after = udp(lab, CLIENT, destination, "routed-restored")
    lab.check("positive", "Restoring the normal response TTL recovers the routed marker without disturbing the approved Service",
              after == marker and query(lab, CURRENT) == "owned-public-marker",
              {"routed_response_restored": after == marker})
    return {"listener_address": destination, "listener_node": listener_node, "client_node": client_node,
            "baseline_response": before, "restricted_routed_response": routed, "restricted_local_response": local,
            "limited_response_log": expected_dispatch if origin_sent else None, "restored_response": after}


def run(lab):
    marker = "owned-public-marker"
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    lab.create(pod(NAME, SERVER))
    lab.create(pod(CLIENT, "import time; time.sleep(240)"))
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

    lifecycle = route_lifecycle(lab, marker)
    hop_limit = verify_hop_limit(lab)
    (lab.evidence / "metadata-endpoint-observations.json").write_text(json.dumps({
        "service_baseline": baseline, "service_lifecycle": lifecycle,
        "ipv4_response_hop_limit": hop_limit, "provider_endpoint_contacted": False,
    }, indent=2) + "\n")
