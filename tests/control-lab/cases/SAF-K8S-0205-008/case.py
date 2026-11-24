"""Verify a declared kube-proxy mode with its actual kernel state and Service behavior."""

import json
import re
import time

SCOPE = "Two Linux Kind nodes with a versioned proxy decision, live nftables ClusterIP state and backend and process lifecycle."
SERVICE = "fixture-proxy"
PORT = 18082
CLIENT = "fixture-proxy-client"
ROLE = "fixture.example/proxy"
MODE = "nftables"
VERSION = "v1.36.1"
APPROVER = "fixture-proxy-reviewer"
READER = "fixture-proxy-operator"
NAMESPACE = "saf-test"
RBAC = "rbac.authorization.k8s.io"
DRIFT = "fixture-proxy-decision-old"
APPROVED = "fixture-proxy-decision-approved"
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


def workload(lab, name, role, node, *argv):
    unit = {"name": "fixture", "image": IMAGE, "command": ["python", *argv],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "5m", "memory": "16Mi"},
                          "limits": {"cpu": "100m", "memory": "64Mi"}}}
    if role != "client":
        unit["readinessProbe"] = {"tcpSocket": {"port": PORT}, "periodSeconds": 1}
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {ROLE: role}},
                "spec": {"nodeName": node, "restartPolicy": "Never", "automountServiceAccountToken": False,
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                             "seccompProfile": {"type": "RuntimeDefault"}},
                         "containers": [unit]}})
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=65s", timeout=75)
    return json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)


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


def grant(lab, user, verbs):
    lab.create({"apiVersion": RBAC + "/v1", "kind": "Role", "metadata": {"name": user},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": verbs}]})
    lab.create({"apiVersion": RBAC + "/v1", "kind": "RoleBinding", "metadata": {"name": user},
                "roleRef": {"apiGroup": RBAC, "kind": "Role", "name": user},
                "subjects": [{"apiGroup": RBAC, "kind": "User", "name": user}]})


def decision(lab, name, mode, actor):
    data = {"scope": "Kind Linux IPv4 ClusterIP TCP", "kubernetes": VERSION, "mode": mode,
            "approver": APPROVER, "decision": name, "requires": "endpoint replacement and proxy recreation",
            "recheck": "Kubernetes, node kernel, proxy configuration or Service route change"}
    obj = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
           "immutable": True, "data": data}
    return lab.kubectl(f"--as={actor}", "create", "-f", "-", "-o", "json", payload=json.dumps(obj), allow_failure=True)


def read_decision(lab, name):
    return json.loads(lab.kubectl(f"--as={READER}", "get", "configmap", name, "-o", "json").stdout)


def proxy_processes(lab):
    ns = ["-n", "kube-system"]
    lab.kubectl(*ns, "rollout", "status", "ds/kube-proxy", "--timeout=65s", timeout=75)
    current = json.loads(lab.kubectl(*ns, "get", "pods", "-l", "k8s-app=kube-proxy", "-o", "json").stdout)["items"]
    records = {}
    for pod in current:
        name = pod["metadata"]["name"]
        if pod["metadata"].get("deletionTimestamp"):
            continue
        status, = pod["status"]["containerStatuses"]
        deadline = time.monotonic() + 25
        while True:
            log = lab.kubectl(*ns, "logs", "pod/" + name).stdout
            modes = re.findall(r"(?i)using (nftables|iptables|ipvs) proxier", log)
            if len(modes) == 1:
                mode = modes[0]
                break
            if time.monotonic() >= deadline:
                lab.block("The active kube-proxy did not report one effective mode: " + name)
            time.sleep(0.4)
        records[pod["spec"]["nodeName"]] = {
            "pod": name, "uid": pod["metadata"]["uid"], "ready": status["ready"], "mode": mode.lower(),
            "container_image": status["imageID"],
        }
    return records


def endpoints(lab):
    rows = json.loads(lab.kubectl("get", "endpointslice", "-l", f"kubernetes.io/service-name={SERVICE}",
                                 "-o", "json").stdout)["items"]
    return sorted(address for row in rows for ep in (row["endpoints"] or []) if ep["conditions"].get("ready")
                  for address in ep["addresses"])


def verified(approval, configured, runtime, owned, version):
    data = approval["data"]
    return (approval["immutable"] and data["kubernetes"] == version and data["mode"] == configured
            and set(runtime) == owned and all(entry["ready"] and entry["mode"] == configured for entry in runtime.values()))


def run(lab):
    client_node, backend_node = lab.cluster + "-control-plane", lab.cluster + "-worker"
    owned = {client_node, backend_node}
    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    if {row["metadata"]["name"] for row in nodes} != owned:
        lab.block("Expected the two owned Kind nodes for kernel-table observations")
    lab.kubectl("label", "namespace", NAMESPACE, "pod-security.kubernetes.io/enforce=restricted")
    grant(lab, APPROVER, ["create"])
    grant(lab, READER, ["get"])
    old_decision = decision(lab, DRIFT, "iptables", APPROVER)
    if old_decision.returncode:
        lab.block("The authorized comparison decision could not be stored")
    old = read_decision(lab, DRIFT)
    refused = decision(lab, APPROVED, MODE, READER)
    unauthorized = refused.returncode != 0 and "cannot create resource" in refused.stderr
    selected = decision(lab, APPROVED, MODE, APPROVER)
    if selected.returncode:
        lab.block("The authorized fixture decision could not be stored")
    approval = read_decision(lab, APPROVED)
    version = json.loads(lab.kubectl("version", "-o", "json").stdout)["serverVersion"]["gitVersion"]

    config = json.loads(lab.kubectl("-n", "kube-system", "get", "configmap", "kube-proxy", "-o", "json").stdout)
    match = re.search(r'(?m)^mode:\s*["\']?([a-z]+)', config["data"]["config.conf"])
    configured = match.group(1) if match else None
    before = proxy_processes(lab)
    workload(lab, CLIENT, "client", client_node, "-c", "import time; time.sleep(320)")
    service = lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": SERVICE},
                          "spec": {"selector": {ROLE: "blue"}, "ports": [{"port": PORT, "targetPort": PORT}]}})
    vip = service["spec"]["clusterIP"]
    empty = eventually(lab, vip, "no-endpoint") == "no-endpoint" and endpoints(lab) == []
    established = verified(approval, configured, before, owned, version)
    mismatch = established and not verified(old, configured, before, owned, version)
    lab.check("red", "The active proxy contradicts the stored comparison decision and the empty Service cannot return a marker",
              mismatch and empty, {"conflicting_stored_mode": mismatch, "empty_service_unavailable": empty})
    lab.check("green", "A separately authorized identity records the matching decision while the reader cannot approve it",
              unauthorized and established, {"reader_write_denied": unauthorized, "approved_mode_matches": established})

    blue = workload(lab, "fixture-blue", "blue", backend_node, "-c", SERVER, "owned-blue")
    blue_reached = eventually(lab, vip, "owned-blue") == "owned-blue"
    blue_endpoints = endpoints(lab)
    before_maps = {node: service_rule(lab, node, vip) for node in sorted(owned)}
    blue_matches = blue_endpoints == [blue["status"]["podIP"]]
    lab.check("green", "Both kernels program the owned tuple and the client receives the exact selected cross-node marker",
              all(before_maps.values()) and blue_reached and blue_matches,
              {"rules_on_two_nodes": all(before_maps.values()), "selected_marker": blue_reached, "endpoint_matches": blue_matches})

    green = workload(lab, "fixture-green", "green", backend_node, "-c", SERVER, "owned-green")
    lab.kubectl("patch", "service", SERVICE, "--type=merge", "-p", json.dumps({"spec": {"selector": {ROLE: "green"}}}))
    green_reached = eventually(lab, vip, "owned-green") == "owned-green"
    green_endpoints = endpoints(lab)
    changed = green_reached and green_endpoints == [green["status"]["podIP"]]
    lab.check("positive", "The Service keeps its tuple and follows the new selected endpoint", changed,
              {"new_marker_and_endpointslice_match": changed})

    lab.kubectl("-n", "kube-system", "rollout", "restart", "ds/kube-proxy")
    after = proxy_processes(lab)
    replaced = set(after) == owned and all(before[node]["uid"] != after[node]["uid"] for node in owned)
    after_maps = {node: service_rule(lab, node, vip) for node in sorted(owned)}
    after_marker = eventually(lab, vip, "owned-green") == "owned-green"
    api_ready = lab.kubectl("get", "--raw", "/readyz", timeout=12).stdout.strip() == "ok"
    recovered = verified(approval, configured, after, owned, version) and all(after_maps.values()) and after_marker
    lab.check("positive", "New kube-proxy Pods recover the same approved mode and Service path",
              replaced and recovered and api_ready, {"proxy_uids_replaced": replaced,
              "required_path_recovered": recovered, "apiserver_ready": api_ready})

    result = {"approval": approval["data"], "approval_uid": approval["metadata"]["uid"],
              "comparison_decision": old["data"], "comparison_decision_rejected": mismatch,
              "reader_create_denied": unauthorized, "configured": configured, "version": version,
              "kernel_versions": {node["metadata"]["name"]: node["status"]["nodeInfo"]["kernelVersion"] for node in nodes},
              "runtime_before": before, "runtime_after": after, "kernel_service_tuple_before": before_maps,
              "kernel_service_tuple_after": after_maps, "cluster_ip": vip, "protocol": "TCP", "port": PORT,
              "observed_endpoints": {"blue": blue_endpoints, "green": green_endpoints}, "marker_after_restart": after_marker}
    (lab.evidence / "proxy-mode-observations.json").write_text(json.dumps(result, indent=2) + "\n")
