"""Exercise CoreDNS upstream selection with inert, cluster-local resolvers."""
import json
import time


NAMESPACE = "saf-test"
ZONE = "saf-0503-009.test"
QUERY = f"approved.{ZONE}"
MARKER_IP = "192.0.2.53"
CONFIG = "saf-0503-009-corefile"
EDITOR = "saf-0503-009-editor"
COREDNS_IMAGE = (
    "coredns/coredns:1.14.2@sha256:"
    "e7e6440cfd1e919280958f5b5a6ab2b184d385bba774c12ad2a9e1e4183f90d9"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
SCOPE = (
    "One disposable kind Kubernetes v1.36.1 cluster with the stock DNS addon disabled, "
    "one case-owned CoreDNS v1.14.2 "
    "deployment with the Kubernetes plugin, and two case-owned UDP DNS stubs in saf-test. "
    "Uses only saf-0503-009.test names and RFC 5737 documentation addresses. Compares the "
    "same query through a baseline Corefile forwarding to the unapproved stub and a hardened "
    "Corefile forwarding only to the approved stub; checks a native cluster Service record, "
    "cache reuse, health/ready HTTP endpoints, configured loop-plugin startup, and scoped "
    "configuration changes through the Kubernetes API. No external "
    "DNS, NodeLocal DNSCache, production cluster, external resolver, or loop-failure exercise."
)


DNS_PROBE = r'''import http.client, json, secrets, socket, struct, sys
def query(server, name):
    ident = secrets.randbits(16)
    labels = name.rstrip('.').split('.')
    q = b''.join(bytes([len(x)]) + x.encode() for x in labels) + b'\0' + struct.pack('!HH', 1, 1)
    packet = struct.pack('!HHHHHH', ident, 0x0100, 1, 0, 0, 0) + q
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    s.sendto(packet, (server, 53)); data, _ = s.recvfrom(4096); s.close()
    if len(data) < 12 or struct.unpack('!H', data[:2])[0] != ident:
        raise RuntimeError('malformed DNS response')
    flags, answers = struct.unpack('!H', data[2:4])[0], struct.unpack('!H', data[6:8])[0]
    if flags & 15: raise RuntimeError('DNS rcode=' + str(flags & 15))
    i = 12
    while data[i] != 0:
        if data[i] & 0xc0 == 0xc0: i += 2; break
        i += data[i] + 1
    else: i += 1
    i += 4
    found = []
    for _ in range(answers):
        if data[i] & 0xc0 == 0xc0: i += 2
        else:
            while data[i] != 0: i += data[i] + 1
            i += 1
        typ, cls, ttl, size = struct.unpack('!HHIH', data[i:i+10]); i += 10
        if typ == 1 and cls == 1 and size == 4: found.append(socket.inet_ntoa(data[i:i+4]))
        i += size
    print(json.dumps({'name': name, 'rcode': flags & 15, 'A': found}, sort_keys=True))
if sys.argv[1] == 'dns': query(sys.argv[2], sys.argv[3])
elif sys.argv[1] == 'http':
    conn = http.client.HTTPConnection(sys.argv[2], int(sys.argv[3]), timeout=3)
    conn.request('GET', sys.argv[4])
    print(json.dumps({'status': conn.getresponse().status}))
    conn.close()
'''

RESOLVER = r'''import socket, struct
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',5353))
while True:
    q, peer=s.recvfrom(4096)
    i=12
    while q[i] != 0: i += q[i]+1
    i += 1
    name=[]; j=12
    while q[j] != 0:
        n=q[j]; name.append(q[j+1:j+1+n].decode()); j += n+1
    qname='.'.join(name).lower()+'.'
    print('query='+qname, flush=True)
    question=q[12:i+4]
    if qname.endswith('.saf-0503-009.test.'):
        answer=b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton('192.0.2.53')
        header=struct.pack('!HHHHHH',struct.unpack('!H',q[:2])[0],0x8180,1,1,0,0)
        s.sendto(header+question+answer,peer)
    else:
        header=struct.pack('!HHHHHH',struct.unpack('!H',q[:2])[0],0x8185,1,0,0,0)
        s.sendto(header+question,peer)
'''

CONFIG_PATCH = r'''import http.client
import json
import os
import ssl
import sys
from pathlib import Path

credentials = Path("/var/run/secrets/kubernetes.io/serviceaccount")
context = ssl.create_default_context(cafile=str(credentials / "ca.crt"))
token = (credentials / "token").read_text().strip()
data = {"data": {"Corefile": sys.argv[2]}}
conn = http.client.HTTPSConnection(os.environ["KUBERNETES_SERVICE_HOST"], timeout=5,
                                   port=int(os.environ["KUBERNETES_SERVICE_PORT"]),
                                   context=context)
try:
    conn.request("PATCH", "/api/v1/namespaces/saf-test/configmaps/" + sys.argv[1],
                 json.dumps(data), {"Authorization": "Bearer " + token,
                                    "Content-Type": "application/merge-patch+json",
                                    "Accept": "application/json"})
    response = conn.getresponse()
    payload = json.loads(response.read(65536))
    print(json.dumps({"code": response.status, "reason": payload.get("reason"),
                      "matches_corefile": payload.get("data", {}).get("Corefile") == sys.argv[2]}))
finally:
    conn.close()
'''


def resource(lab, value):
    if value.get("kind") not in ("ClusterRole", "ClusterRoleBinding"):
        value.setdefault("metadata", {}).setdefault("namespace", NAMESPACE)
    return lab.create(value)


def wait_pod(lab, name):
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=90s", timeout=100)
    item = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
    return item["status"]["podIP"]


def dns_probe(lab, pod, server, qname, *, retryable=False):
    result = lab.kubectl("exec", pod, "--", "python", "-c", DNS_PROBE,
                         "dns", server, qname, timeout=15, allow_failure=retryable)
    if result.returncode:
        return {}
    return json.loads(result.stdout.strip())


def log_count(lab, name, qname):
    output = lab.kubectl("logs", f"pod/{name}", timeout=20).stdout
    return sum(line.strip() == "query=" + qname.lower().rstrip(".") + "." for line in output.splitlines())


def wait_for_forwarding(lab, service_ip, resolver):
    # A separate name leaves the measured query uncached when kube-proxy converges.
    readiness_query = f"ready-{resolver}.{ZONE}"
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        result = dns_probe(lab, "saf-0503-009-probe", service_ip, readiness_query, retryable=True)
        if (result.get("A") == [MARKER_IP]
                and log_count(lab, f"saf-0503-009-{resolver}", readiness_query)):
            return
        time.sleep(0.5)
    lab.block(f"The CoreDNS Service did not forward to the {resolver} fixture after rollout")


def query_after_rollout(lab, service_ip):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        response = dns_probe(lab, "saf-0503-009-probe", service_ip, QUERY, retryable=True)
        if response:
            return response
    lab.block("The measured DNS query did not receive a response after rollout")


def make_corefile(upstream_ip):
    return (
        ".:1053 {\n"
        "    errors\n"
        "    health :8080\n"
        "    ready :8181\n"
        "    loop\n"
        "    kubernetes cluster.local {\n"
        "        pods disabled\n"
        "        fallthrough in-addr.arpa ip6.arpa\n"
        "        ttl 30\n"
        "    }\n"
        "    forward . " + upstream_ip + ":5353 {\n"
        "        max_fails 0\n"
        "    }\n"
        "    cache 30\n"
        "}\n"
    )


def resolver_pod(name):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "labels": {"app": name}},
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Always",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "runAsGroup": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "resolver", "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-u", "-c", RESOLVER],
                "ports": [{"name": "dns", "containerPort": 5353, "protocol": "UDP"}],
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]},
                                    "readOnlyRootFilesystem": True},
                "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                              "limits": {"cpu": "100m", "memory": "32Mi"}},
            }],
        },
    }


def core_resources(corefile):
    return [
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "saf-0503-009-coredns"}},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
         "metadata": {"name": "saf-0503-009-coredns"},
         "rules": [{"apiGroups": [""], "resources": ["services", "endpoints", "namespaces"],
                    "verbs": ["list", "watch"]},
                   {"apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"],
                    "verbs": ["list", "watch"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
         "metadata": {"name": "saf-0503-009-coredns"},
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                     "name": "saf-0503-009-coredns"},
         "subjects": [{"kind": "ServiceAccount", "name": "saf-0503-009-coredns", "namespace": NAMESPACE}]},
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "saf-0503-009-corefile"},
         "data": {"Corefile": corefile}},
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "saf-0503-009-coredns"},
         "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "saf-0503-009-coredns"}},
                  "template": {"metadata": {"labels": {"app": "saf-0503-009-coredns"}},
                               "spec": {"serviceAccountName": "saf-0503-009-coredns",
                                        "automountServiceAccountToken": True,
                                        "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                                            "runAsGroup": 65532,
                                                            "seccompProfile": {"type": "RuntimeDefault"}},
                                        "containers": [{"name": "coredns", "image": COREDNS_IMAGE,
                                                        "imagePullPolicy": "IfNotPresent",
                                                        "args": ["-conf", "/etc/coredns/Corefile"],
                                                        "ports": [{"name": "dns", "containerPort": 1053,
                                                                   "protocol": "UDP"},
                                                                  {"name": "health", "containerPort": 8080},
                                                                  {"name": "ready", "containerPort": 8181}],
                                                        "readinessProbe": {"httpGet": {"path": "/ready", "port": 8181},
                                                                           "initialDelaySeconds": 2, "periodSeconds": 2},
                                                        "livenessProbe": {"httpGet": {"path": "/health", "port": 8080},
                                                                          "initialDelaySeconds": 2, "periodSeconds": 5},
                                                        "securityContext": {"allowPrivilegeEscalation": False,
                                                                            "capabilities": {"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]},
                                                                            "readOnlyRootFilesystem": True},
                                                        "resources": {"requests": {"cpu": "25m", "memory": "32Mi"},
                                                                      "limits": {"cpu": "250m", "memory": "96Mi"}},
                                                        "volumeMounts": [{"name": "corefile", "mountPath": "/etc/coredns",
                                                                          "readOnly": True}]}],
                                        "volumes": [{"name": "corefile", "configMap": {"name": "saf-0503-009-corefile"}}]}}}},
        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "saf-0503-009-coredns"},
         "spec": {"selector": {"app": "saf-0503-009-coredns"},
                  "ports": [{"name": "dns", "port": 53, "targetPort": 1053, "protocol": "UDP"}]}}
    ]


def check_native_service(lab, dns_ip):
    service = json.loads(lab.kubectl("get", "service", "kubernetes", "-n", "default", "-o", "json").stdout)
    expected = service["spec"]["clusterIP"]
    result = dns_probe(lab, "saf-0503-009-probe", dns_ip, "kubernetes.default.svc.cluster.local")
    lab.check("positive", "The isolated CoreDNS copy still resolves the native Kubernetes Service",
              result["A"] == [expected], {"service": "kubernetes.default.svc.cluster.local",
                                          "native_service_ip_matched": result["A"] == [expected]})


def authorize_config_update(lab, corefile):
    resource(lab, {"apiVersion": "v1", "kind": "ServiceAccount",
                   "metadata": {"name": EDITOR}})
    editor = resolver_pod(EDITOR)
    editor["spec"].update({"serviceAccountName": EDITOR, "automountServiceAccountToken": True})
    container = editor["spec"]["containers"][0]
    container["command"] = ["python", "-c", "import time; time.sleep(3600)"]
    del container["ports"]
    resource(lab, editor)
    wait_pod(lab, EDITOR)

    def update(name):
        result = lab.kubectl("exec", EDITOR, "--", "python", "-c", CONFIG_PATCH,
                             name, corefile, timeout=15)
        return json.loads(result.stdout)

    unauthorized = update(CONFIG)
    lab.check("red", "The fixture identity cannot update the Corefile before its named RBAC grant",
              unauthorized == {"code": 403, "reason": "Forbidden", "matches_corefile": False},
              unauthorized)
    resource(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                   "metadata": {"name": EDITOR},
                   "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                              "resourceNames": [CONFIG], "verbs": ["patch"]}]})
    resource(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                   "metadata": {"name": EDITOR},
                   "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                               "name": EDITOR},
                   "subjects": [{"kind": "ServiceAccount", "name": EDITOR, "namespace": NAMESPACE}]})

    deadline = time.monotonic() + 15
    approved = update(CONFIG)
    while approved["code"] == 403 and time.monotonic() < deadline:
        time.sleep(0.5)
        approved = update(CONFIG)
    lab.check("green", "The same identity updates the exact Corefile after its scoped grant",
              approved == {"code": 200, "reason": None, "matches_corefile": True}, approved)
    other = f"{CONFIG}-comparison"
    resource(lab, {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": other}})
    unapproved_change = update(other)
    lab.check("positive", "The grant cannot update an unrelated ConfigMap",
              unapproved_change == {"code": 403, "reason": "Forbidden", "matches_corefile": False},
              unapproved_change)


def run(lab):
    server = json.loads(lab.kubectl("version", "-o", "json").stdout)["serverVersion"].get("gitVersion")
    lab.check("positive", "Case uses Kubernetes v1.36.1", server == "v1.36.1", server)

    addon = lab.kubectl("get", "deployment/coredns", "service/kube-dns",
                         "-n", "kube-system", "--ignore-not-found", "-o", "name")
    ready = lab.kubectl("get", "--raw=/readyz").stdout.strip() == "ok"
    lab.check("red", "Kubernetes is Ready with kubeadm's CoreDNS addon disabled",
              ready and not addon.stdout.strip(),
              {"api_ready": ready, "stock_coredns_deployment_and_service_absent": not addon.stdout.strip()})

    for name in ("saf-0503-009-unapproved", "saf-0503-009-approved"):
        resource(lab, resolver_pod(name))
        ip = wait_pod(lab, name)
        lab.check("positive", f"Owned inert resolver {name} is ready", bool(ip), {"has_pod_ip": bool(ip)})

    unapproved_ip = json.loads(lab.kubectl("get", "pod", "saf-0503-009-unapproved", "-o", "json").stdout)["status"]["podIP"]
    approved_ip = json.loads(lab.kubectl("get", "pod", "saf-0503-009-approved", "-o", "json").stdout)["status"]["podIP"]
    resource(lab, {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "saf-0503-009-probe"},
                   "spec": {"automountServiceAccountToken": False,
                            "containers": [{"name": "probe", "image": PYTHON_IMAGE,
                                            "imagePullPolicy": "IfNotPresent",
                                            "command": ["python", "-c", "import time; time.sleep(3600)"],
                                            "securityContext": {"allowPrivilegeEscalation": False,
                                                                "capabilities": {"drop": ["ALL"]},
                                                                "runAsNonRoot": True, "runAsUser": 65534,
                                                                "readOnlyRootFilesystem": True,
                                                                "seccompProfile": {"type": "RuntimeDefault"}}}]}})
    wait_pod(lab, "saf-0503-009-probe")

    # Red phase: only the owned unapproved resolver can answer the safe test name.
    for obj in core_resources(make_corefile(unapproved_ip)):
        resource(lab, obj)
    lab.kubectl("rollout", "status", "deployment/saf-0503-009-coredns", "--timeout=90s", timeout=100)
    dns_ip = json.loads(lab.kubectl("get", "service", "saf-0503-009-coredns", "-o", "json").stdout)["spec"]["clusterIP"]
    wait_for_forwarding(lab, dns_ip, "unapproved")
    red = query_after_rollout(lab, dns_ip)
    unapproved_before = log_count(lab, "saf-0503-009-unapproved", QUERY)
    approved_in_baseline = log_count(lab, "saf-0503-009-approved", QUERY)
    lab.check("red", "Baseline forwarding sends the safe test query to the unapproved inert resolver",
              red.get("A") == [MARKER_IP] and unapproved_before > 0 and approved_in_baseline == 0,
              {"query": QUERY, "answer": red, "unapproved_query_observed": unapproved_before > 0,
               "approved_query_observed": approved_in_baseline > 0})

    # Green phase: change only the forwarding target. Restart clears the per-process cache.
    authorize_config_update(lab, make_corefile(approved_ip))
    lab.kubectl("rollout", "restart", "deployment/saf-0503-009-coredns")
    lab.kubectl("rollout", "status", "deployment/saf-0503-009-coredns", "--timeout=90s", timeout=100)
    wait_for_forwarding(lab, dns_ip, "approved")
    approved_before = log_count(lab, "saf-0503-009-approved", QUERY)
    unapproved_before_green = log_count(lab, "saf-0503-009-unapproved", QUERY)
    green = query_after_rollout(lab, dns_ip)
    approved_after = log_count(lab, "saf-0503-009-approved", QUERY)
    unapproved_after = log_count(lab, "saf-0503-009-unapproved", QUERY)
    lab.check("green", "Hardened forwarding sends the same safe query only to the configured resolver",
              green.get("A") == [MARKER_IP] and approved_after > approved_before
              and unapproved_after == unapproved_before_green,
              {"query": QUERY, "answer": green,
               "approved_query_observed": approved_after > approved_before,
               "unapproved_query_delta": unapproved_after - unapproved_before_green})

    check_native_service(lab, dns_ip)
    repeated = dns_probe(lab, "saf-0503-009-probe", dns_ip, QUERY)
    approved_cached = log_count(lab, "saf-0503-009-approved", QUERY)
    lab.check("positive", "A repeated safe query is answered from the configured cache",
              repeated.get("A") == [MARKER_IP] and approved_cached == approved_after,
              {"query": QUERY, "answer": repeated, "upstream_query_count_unchanged": approved_cached == approved_after})

    pod_rows = json.loads(lab.kubectl("get", "pod", "-l", "app=saf-0503-009-coredns",
                                     "-o", "json").stdout)["items"]
    probe_pod = next(row["status"]["podIP"] for row in pod_rows
                     if not row["metadata"].get("deletionTimestamp"))
    for path, port in (("/health", 8080), ("/ready", 8181)):
        result = lab.kubectl("exec", "saf-0503-009-probe", "--", "python", "-c", DNS_PROBE,
                             "http", probe_pod, str(port), path, timeout=15)
        observed = json.loads(result.stdout.strip())
        lab.check("positive", f"Configured CoreDNS {path} endpoint returns HTTP 200",
                  observed.get("status") == 200,
                  {"path": path, "status": observed.get("status")})

    config = make_corefile(approved_ip)
    logs = lab.kubectl("logs", "deployment/saf-0503-009-coredns", timeout=20).stdout.lower()
    loop_warning = "plugin/loop: loop (" in logs
    loop_present = "    loop\n" in config and not loop_warning
    lab.check("positive", "CoreDNS starts with the loop plugin configured and no loop warning",
              loop_present, {"loop_plugin_configured": "    loop\n" in config,
                             "loop_warning_observed": loop_warning})
