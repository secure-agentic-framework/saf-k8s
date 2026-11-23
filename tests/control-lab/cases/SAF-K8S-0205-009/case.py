"""Verify actual kube-proxy API permissions and preserve owned Service routing."""

import json
import time

SCOPE = "A native Kind kube-proxy identity receives and loses one unnecessary fixture API permission while its ClusterIP serves traffic."
SERVICE = "fixture-proxy"
PORT = 18082
CLIENT = "fixture-proxy-client"
ROLE = "fixture.example/proxy"
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


MARKER = "fixture-proxy-private-config"
GRANT = "fixture-extra-proxy-reader"


def permitted(lab, account, attributes):
    resource = {"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview", "spec": {
        "user": f"system:serviceaccount:kube-system:{account}",
        "groups": ["system:serviceaccounts", "system:serviceaccounts:kube-system", "system:authenticated"],
        "resourceAttributes": attributes,
    }}
    result = lab.create(resource)["status"]
    return result.get("allowed") is True


def grant(lab, account):
    base = {"apiVersion": "rbac.authorization.k8s.io/v1", "metadata": {"name": GRANT}}
    lab.create({**base, "kind": "Role", "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                "verbs": ["get"], "resourceNames": [MARKER]}]})
    lab.create({**base, "kind": "RoleBinding",
                "subjects": [{"kind": "ServiceAccount", "name": account, "namespace": "kube-system"}],
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": GRANT}})


def wait_for(lab, account, attributes, expected):
    actual = permitted(lab, account, attributes)
    deadline = time.monotonic() + 12
    while actual != expected and time.monotonic() < deadline:
        time.sleep(0.3)
        actual = permitted(lab, account, attributes)
    return actual


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    lab.kubectl("-n", "kube-system", "rollout", "status", "ds/kube-proxy", "--timeout=65s", timeout=75)
    daemon = json.loads(lab.kubectl("-n", "kube-system", "get", "ds/kube-proxy", "-o", "json").stdout)
    spec = daemon["spec"]["template"]["spec"]
    account = spec["serviceAccountName"]
    if account != "kube-proxy":
        lab.block("The lab expects the native kube-proxy account")
    unit, = spec["containers"]
    observed_security = unit.get("securityContext", {})
    attributes = {"verb": "get", "group": "", "resource": "configmaps", "name": MARKER, "namespace": "saf-test"}
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": MARKER},
                "immutable": True, "data": {"mark": "synthetic nonsecret artifact"}})
    original_denied = not permitted(lab, account, attributes)
    grant(lab, account)
    expanded = wait_for(lab, account, attributes, True)
    lab.check("red", "The active native proxy identity gains an unnecessary owned-object permission when an extra grant is present",
              original_denied and expanded, {"baseline_denied": original_denied, "fixture_grant_expanded_access": expanded})
    lab.kubectl("delete", "rolebinding", GRANT)
    removed = not wait_for(lab, account, attributes, False)
    reads = {resource: permitted(lab, account, {"verb": "list", "group": group, "resource": resource})
             for group, resource in (("", "services"), ("discovery.k8s.io", "endpointslices"))}
    lab.check("green", "Removing the extra grant restores the API boundary while retaining required Service and EndpointSlice access",
              removed and all(reads.values()), {"unnecessary_get_denied_again": removed, "required_reads": reads})
    workload(lab, CLIENT, "client", "-c", "import time; time.sleep(120)")
    workload(lab, "fixture-proxy-backend", "blue", "-c", SERVER, "owned-proxy-service")
    service = lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": SERVICE},
                          "spec": {"selector": {ROLE: "blue"}, "ports": [{"port": PORT, "targetPort": PORT}]}})
    reached = eventually(lab, service["spec"]["clusterIP"], "owned-proxy-service") == "owned-proxy-service"
    lab.check("positive", "The active proxy retains the approved Service behavior after rights are narrowed",
              reached, {"owned_service_reachable": reached})
    (lab.evidence / "proxy-permission-observations.json").write_text(json.dumps({
        "observed_proxy_identity": f"kube-system/{account}", "unnecessary_fixture_get_revoked": removed,
        "required_reads": reads, "default_proxy_pod_host_network": spec.get("hostNetwork", False),
        "default_proxy_container_privileged": observed_security.get("privileged", False),
        "owned_service_reached": reached, "host_privileges_changed": False,
    }, indent=2) + "\n")
