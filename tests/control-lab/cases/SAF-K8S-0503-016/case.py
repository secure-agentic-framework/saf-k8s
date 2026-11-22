"""Bounded cross-namespace DNS name-policy case for SAF-K8S-0503-016."""
from hashlib import sha256
import json
import time


CONTROL_ID = "SAF-K8S-0503-016"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
CILIUM_VERSION = "1.20.5"
CILIUM_CHART_SHA256 = "0c7592eb75179ecf46dd3ec22145916f0164c4401214ea15afb5b230b1d11a21"
SOURCE_NS = "saf-0503-016-clients"
SERVICE_NS = "saf-0503-016-services"
ROLE_KEY = "saf-k8s.example/0503-016-role"
SERVICE_KEY = "saf-k8s.example/0503-016-service"
SELECTED = "saf-0503-016-selected-client"
COMPARATOR = "saf-0503-016-unselected-comparator"
ALLOWED = "saf-0503-016-approved-service"
DENIED = "saf-0503-016-unapproved-service"
ALLOWED_NAME = f"{ALLOWED}.{SERVICE_NS}.svc.cluster.local."
DENIED_NAME = f"{DENIED}.{SERVICE_NS}.svc.cluster.local."
PORT = 8080
SERVICE_IPS = {ALLOWED: "10.96.240.50", DENIED: "10.96.240.51"}
SCOPE = (
    "Fresh disposable Kubernetes v1.36.1 Kind cluster. Pinned Cilium 1.20.5 "
    "enrolls the new CoreDNS and fixture Pods. Two fixed, case-owned cross-namespace "
    "Service A records are queried through cluster DNS before and after installing "
    "an exact DNS-name allowlist. The policy targets one source Pod. Its approved "
    "answer persists, the unapproved question receives REFUSED, and the comparison "
    "Pod retains both answers. This checks discovery of the two records over UDP, "
    "with deployed CNI coverage, other record types, and service reachability out of scope."
)


def kubectl(lab, *args, timeout=45, **kwargs):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        f"--request-timeout={max(5, timeout - 5)}s", *args, timeout=timeout, **kwargs,
    )


def get_json(lab, *args):
    return json.loads(kubectl(lab, *args, "-o", "json").stdout)


def create(lab, resource):
    kubectl(lab, "create", "-f", "-", payload=json.dumps(resource))


def wait_ready(lab, namespace, kind, name):
    kubectl(lab, "-n", namespace, "wait", "--for=condition=Ready", f"{kind}/{name}",
            "--timeout=120s", timeout=130)


def pod(name, namespace, labels, command):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace, "labels": labels},
        "spec": {
            "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                "runAsGroup": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "fixture", "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-u", "-c", command],
                "readinessProbe": {"exec": {"command": ["python", "-c", "pass"]},
                                   "periodSeconds": 2, "failureThreshold": 10},
                "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                              "limits": {"cpu": "100m", "memory": "64Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]},
                                    "readOnlyRootFilesystem": True},
            }],
        },
    }


DNS_PROBE = r'''import json, secrets, socket, struct, sys
name = sys.argv[1]
resolver = next(line.split()[1] for line in open("/etc/resolv.conf") if line.startswith("nameserver "))
expected = {"saf-0503-016-approved-service.saf-0503-016-services.svc.cluster.local.":"10.96.240.50",
            "saf-0503-016-unapproved-service.saf-0503-016-services.svc.cluster.local.":"10.96.240.51"}.get(name)
ident = secrets.randbits(16)
q = b"".join(bytes([len(x)])+x.encode("ascii") for x in name.rstrip(".").split("."))+b"\0"+struct.pack("!HH",1,1)
packet = struct.pack("!HHHHHH",ident,0x0100,1,0,0,0)+q
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)
try:
 s.sendto(packet,(resolver,53)); data,_=s.recvfrom(4096)
 valid=len(data)>=12 and struct.unpack("!H",data[:2])[0]==ident
 rcode=(struct.unpack("!H",data[2:4])[0]&15) if valid else -1
 answers=struct.unpack("!H",data[6:8])[0] if valid else 0
 pos=12
 while pos<len(data) and data[pos]!=0:
  if data[pos]&0xc0==0xc0: pos+=2; break
  pos+=data[pos]+1
 else: pos+=1
 pos+=4; addresses=[]
 for _ in range(answers):
  if pos+2>len(data): break
  if data[pos]&0xc0==0xc0: pos+=2
  else:
   while pos<len(data) and data[pos]!=0: pos+=data[pos]+1
   pos+=1
  if pos+10>len(data): break
  typ,cls,ttl,size=struct.unpack("!HHIH",data[pos:pos+10]); pos+=10
  if typ==1 and cls==1 and size==4 and pos+size<=len(data): addresses.append(socket.inet_ntoa(data[pos:pos+size]))
  pos+=size
 print(json.dumps({"valid_response":valid,"rcode":rcode,"answer_matches":addresses==[expected]},sort_keys=True))
except (OSError,TimeoutError): print(json.dumps({"valid_response":False,"rcode":-1,"has_answer":False},sort_keys=True))
finally: s.close()
'''

CLIENT_SLEEP = "import time; time.sleep(3600)"


def service(name):
    return {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": name, "namespace": SERVICE_NS,
                     "labels": {SERVICE_KEY: name}},
        "spec": {"type": "ClusterIP", "clusterIP": SERVICE_IPS[name],
                 "clusterIPs": [SERVICE_IPS[name]], "selector": {SERVICE_KEY: name},
                 "ports": [{"name": "http", "port": PORT, "targetPort": PORT,
                            "protocol": "TCP"}]},
    }


def cilium_policy():
    return {
        "apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
        "metadata": {"name": "saf-0503-016-selected-discovery", "namespace": SOURCE_NS},
        "spec": {
            "endpointSelector": {"matchLabels": {ROLE_KEY: "selected"}},
            "egress": [
                {"toEndpoints": [{"matchLabels": {
                    "k8s:io.kubernetes.pod.namespace": "kube-system",
                    "k8s:k8s-app": "kube-dns"}}],
                 "toPorts": [{"ports": [{"port": "53", "protocol": "ANY"}],
                              "rules": {"dns": [{"matchName": ALLOWED_NAME}]}}]},
            ],
        },
    }


def run_probe(lab, source_pod, name, *, expected_allowed):
    result = kubectl(lab, "-n", SOURCE_NS, "exec", f"pod/{source_pod}", "--",
                     "python", "-c", DNS_PROBE, name, timeout=15)
    observed = json.loads(result.stdout.strip())
    matched = (observed.get("valid_response") is True and observed.get("rcode") == 0
               and observed.get("answer_matches") is True) if expected_allowed else (
                   observed.get("valid_response") is True and observed.get("rcode") == 5)
    return matched


def expect_dns(lab, phase, source_pod, name, expected_allowed):
    consecutive = 0
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        consecutive = consecutive + 1 if run_probe(
            lab, source_pod, name, expected_allowed=expected_allowed) else 0
        if consecutive >= 2:
            break
        time.sleep(0.5)
    lab.check(phase, f"Bounded DNS policy result for {source_pod}/{name}", consecutive >= 2,
              {"source_pod": source_pod, "qname": name, "expected_allowed": expected_allowed,
               "expected_dns_refused": not expected_allowed,
               "two_consecutive_observations": consecutive >= 2})


def install_cilium(lab):
    config_dir = lab.kubeconfig.parent
    registry = config_dir / "helm-registry.json"
    lab.command("helm", "pull", "oci://quay.io/cilium/charts/cilium",
                "--version", CILIUM_VERSION, "--destination", str(config_dir),
                "--registry-config", str(registry), timeout=120)
    chart = config_dir / f"cilium-{CILIUM_VERSION}.tgz"
    pinned = sha256(chart.read_bytes()).hexdigest() == CILIUM_CHART_SHA256
    if not pinned:
        lab.block("Pinned Cilium chart digest does not match")
    lab.command("helm", "upgrade", "--install", "cilium", str(chart),
                "--kubeconfig", str(lab.kubeconfig), "--kube-context", f"kind-{lab.cluster}",
                "--namespace", "kube-system", "--registry-config", str(registry),
                "--set", "ipam.mode=kubernetes,cni.exclusive=true,l7Proxy=true,operator.replicas=1",
                "--wait", "--timeout", "5m", timeout=320)
    kubectl(lab, "-n", "kube-system", "rollout", "status", "daemonset/cilium",
            "--timeout=120s", timeout=130)
    # Recreate the DNS Pods so Cilium owns their endpoints as well as the probe endpoints.
    kubectl(lab, "-n", "kube-system", "rollout", "restart", "deployment/coredns")
    kubectl(lab, "-n", "kube-system", "rollout", "status", "deployment/coredns",
            "--timeout=120s", timeout=130)
    lab.check("positive", f"Pinned Cilium {CILIUM_VERSION} and replacement CoreDNS are ready",
              pinned, {"cilium_version": CILIUM_VERSION, "chart_digest_matches": pinned})


def wait_for_cilium_endpoints(lab):
    deadline = time.monotonic() + 30
    while True:
        dns = get_json(lab, "-n", "kube-system", "get", "pods", "-l", "k8s-app=kube-dns")
        dns_pods = {p["metadata"]["name"] for p in dns["items"]
                    if not p["metadata"].get("deletionTimestamp")}
        groups = (("kube-system", dns_pods), (SOURCE_NS, {SELECTED, COMPARATOR}))
        managed = []
        for namespace, names in groups:
            endpoints = get_json(lab, "-n", namespace, "get", "ciliumendpoints")["items"]
            assigned = {entry["metadata"]["name"] for entry in endpoints
                        if entry.get("status", {}).get("identity", {}).get("id", 0) > 1}
            managed.append(bool(names) and names <= assigned)
        if all(managed) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check("positive", "Cilium assigned identities to CoreDNS and both probe Pods",
              all(managed), {"dns_managed": managed[0], "both_clients_managed": managed[1]})


def run(lab):
    kind = lab.command("kind", "version").stdout.strip()
    server_version = json.loads(kubectl(lab, "version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    lab.check("positive", "Pinned Kubernetes v1.36.1 Kind control plane",
              server_version == "v1.36.1", {"kind_version": kind,
                                           "kubernetes_version": server_version})
    install_cilium(lab)
    create(lab, {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": SOURCE_NS}})
    create(lab, {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": SERVICE_NS}})
    for name in (ALLOWED, DENIED):
        create(lab, pod(name, SERVICE_NS, {SERVICE_KEY: name}, CLIENT_SLEEP))
        create(lab, service(name))
    create(lab, pod(SELECTED, SOURCE_NS, {ROLE_KEY: "selected"}, CLIENT_SLEEP))
    create(lab, pod(COMPARATOR, SOURCE_NS, {ROLE_KEY: "comparison"}, CLIENT_SLEEP))
    for name in (ALLOWED, DENIED):
        wait_ready(lab, SERVICE_NS, "pod", name)
    for name in (SELECTED, COMPARATOR):
        wait_ready(lab, SOURCE_NS, "pod", name)
    wait_for_cilium_endpoints(lab)
    # Red arm: both namespace-qualified Service names resolve before enrollment policy.
    for client in (SELECTED, COMPARATOR):
        expect_dns(lab, "red", client, ALLOWED_NAME, True)
        expect_dns(lab, "red", client, DENIED_NAME, True)

    # Exact Pod-label enrollment and resolver identity scope.
    create(lab, cilium_policy())
    kubectl(lab, "-n", SOURCE_NS, "get", "ciliumnetworkpolicy",
            "saf-0503-016-selected-discovery", "-o", "name")
    expect_dns(lab, "green", SELECTED, ALLOWED_NAME, True)
    expect_dns(lab, "green", SELECTED, DENIED_NAME, False)
    expect_dns(lab, "positive", COMPARATOR, ALLOWED_NAME, True)
    expect_dns(lab, "positive", COMPARATOR, DENIED_NAME, True)
