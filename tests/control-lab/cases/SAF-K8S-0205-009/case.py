"""Verify actual kube-proxy API permissions and preserve owned Service routing."""

import json
import time

SCOPE = "Actual requests under the native kube-proxy identity, observed process state and retained Service traffic after narrowing fixture privileges."
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


def proxy_request(lab, account, *args):
    return lab.kubectl(f"--as=system:serviceaccount:kube-system:{account}",
                       "--as-group=system:serviceaccounts", "--as-group=system:serviceaccounts:kube-system",
                       "--as-group=system:authenticated", *args, allow_failure=True, timeout=14)


def process_state(lab):
    rows = json.loads(lab.kubectl("-n", "kube-system", "get", "pods", "-l", "k8s-app=kube-proxy", "-o", "json").stdout)
    live, = rows["items"]
    node = live["spec"]["nodeName"]
    if node != lab.cluster + "-control-plane":
        lab.block("Expected the case-owned Kind control-plane node")
    status, = live["status"]["containerStatuses"]
    container_id = status["containerID"].split("://", 1)[1]
    contained = json.loads(lab.command("docker", "exec", node, "crictl", "inspect", container_id).stdout)
    pid = int(contained["info"]["pid"])
    effective = lab.command("docker", "exec", node, "cat", f"/proc/{pid}/status").stdout
    initial = dict(line.split(":", 1) for line in effective.splitlines() if ":" in line)
    children = lab.command("docker", "exec", node, "cat", f"/proc/{pid}/task/{pid}/children").stdout.split()
    if initial["Name"].strip() != "kube-proxy":
        for child in children:
            details = lab.command("docker", "exec", node, "cat", f"/proc/{int(child)}/status",
                                  allow_failure=True).stdout
            matching = dict(line.split(":", 1) for line in details.splitlines() if ":" in line)
            if matching.get("Name", "").strip() == "kube-proxy":
                pid, initial = int(child), matching
                break
    if initial["Name"].strip() != "kube-proxy":
        lab.block("The actual kube-proxy process could not be attributed to the fixture container")
    permits = int(initial["CapEff"].strip(), 16)
    mounts = lab.command("docker", "exec", node, "cat", f"/proc/{pid}/mountinfo").stdout
    mountpoints = {parts[4]: parts[5] for parts in map(str.split, mounts.splitlines())
                   if parts[4] in {"/proc", "/proc/sys"}}
    if not mountpoints:
        lab.block("No covering mount was found for the live proxy sysctl path")
    sysctl_mount = max(mountpoints, key=len)
    return {"pod_uid": live["metadata"]["uid"], "image": status["imageID"], "pid": pid,
            "command": initial["Name"].strip(), "effective_capabilities": f"{permits:x}",
            "net_admin": bool(permits & (1 << 12)), "sys_admin": bool(permits & (1 << 21)), "proc_sys_mount": sysctl_mount, "proc_sys_flags": mountpoints[sysctl_mount]}


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
    marker_path = f"/api/v1/namespaces/saf-test/configmaps/{MARKER}"
    first_reply = proxy_request(lab, account, "get", "--raw", marker_path)
    original_denied = not permitted(lab, account, attributes) and first_reply.returncode != 0 and "Forbidden" in first_reply.stderr
    grant(lab, account)
    expanded = wait_for(lab, account, attributes, True)
    granted = proxy_request(lab, account, "get", "--raw", marker_path)
    marker_read = granted.returncode == 0 and json.loads(granted.stdout)["data"]["mark"] == "synthetic nonsecret artifact"
    lab.check("red", "The real ConfigMap request returns the fixture only when the extra grant is active",
              original_denied and expanded and marker_read, {"baseline_denied": original_denied,
              "fixture_grant_expanded_access": expanded, "direct_fixture_read_worked": marker_read})
    lab.kubectl("delete", "rolebinding", GRANT)
    removed = not wait_for(lab, account, attributes, False)
    reply = proxy_request(lab, account, "get", "--raw", marker_path)
    still_denied = reply.returncode != 0 and "Forbidden" in reply.stderr
    reads = {}
    for resource, path in {"services": "/api/v1/services",
                           "endpointslices": "/apis/discovery.k8s.io/v1/endpointslices"}.items():
        listed = proxy_request(lab, account, "get", "--raw", path + "?limit=1")
        watched = proxy_request(lab, account, "get", "--raw", path + "?watch=true&timeoutSeconds=2")
        reads[resource] = listed.returncode == 0 and watched.returncode == 0
    lab.check("green", "An actual request is denied after removing the grant while ordinary lists and watches remain authorized",
              removed and still_denied and all(reads.values()),
              {"unnecessary_get_denied_again": removed and still_denied, "required_lists_and_watches": reads})
    observed = process_state(lab)
    native = observed_security.get("privileged", False) and spec.get("hostNetwork", False)
    lab.check("positive", "The running baseline proxy retains effective network and system capabilities independently of API rights",
              native and observed["net_admin"] and observed["sys_admin"],
              {"native_host_network_and_privileged": native, "observed_net_admin": observed["net_admin"],
               "observed_sys_admin": observed["sys_admin"]})
    workload(lab, CLIENT, "client", "-c", "import time; time.sleep(120)")
    workload(lab, "fixture-proxy-backend", "blue", "-c", SERVER, "owned-proxy-service")
    service = lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": SERVICE},
                          "spec": {"selector": {ROLE: "blue"}, "ports": [{"port": PORT, "targetPort": PORT}]}})
    reached = eventually(lab, service["spec"]["clusterIP"], "owned-proxy-service") == "owned-proxy-service"
    lab.check("positive", "The active proxy retains the approved Service behavior after rights are narrowed",
              reached, {"owned_service_reachable": reached})
    (lab.evidence / "proxy-permission-observations.json").write_text(json.dumps({
        "observed_proxy_identity": f"kube-system/{account}", "unnecessary_fixture_get_revoked": removed,
        "required_reads": reads, "direct_configmap_read": {"before_grant_denied": original_denied,
            "with_grant": marker_read, "after_revocation_denied": still_denied},
        "live_process": observed, "default_proxy_pod_host_network": spec.get("hostNetwork", False),
        "default_proxy_container_privileged": observed_security.get("privileged", False),
        "owned_service_reached": reached, "host_privileges_changed": False,
    }, indent=2) + "\n")
