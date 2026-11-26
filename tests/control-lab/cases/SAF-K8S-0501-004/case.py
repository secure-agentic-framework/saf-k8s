"""Exercise Cilium HTTP, DNS, and cluster-wide policy on owned workloads."""
from hashlib import sha256
from ipaddress import IPv4Address
import json
from pathlib import Path
import shlex
import time


CONTROL_ID = "SAF-K8S-0501-004"
CILIUM_VERSION = "1.20.5"
CILIUM_CHART_SHA256 = "0c7592eb75179ecf46dd3ec22145916f0164c4401214ea15afb5b230b1d11a21"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
BUSYBOX_IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
NAMESPACE = "saf-0501-004"
CLIENT = "owned-http-client"
SERVER = "owned-http-server"
PORT = 8080
MARKER = "saf-0501-004-owned-harmless-response-6f83"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
SCOPE = (
    "Cilium 1.20.5 on kind v0.32.0 / Kubernetes v1.36.1. The retained L7 "
    "ingress claim is IPv4 TCP/8080 between owned Pods with direct Pod-IP "
    "requests to /safe. Additional local claims cover toFQDNs against two "
    "synthetic .test names on an internal Docker bridge, plus CiliumClusterwideNetworkPolicy "
    "selection and deny precedence across two selected namespaces and one unaffected namespace. "
    "No public endpoint, production policy, other CNI, or provider integration is exercised."
)

DNS_FIXTURE = "owned-dns-fixture"
DNS_PORT = 53
APPROVED_NAME = "approved.saf-0501-004.test"
ALTERNATE_NAME = "alternate.saf-0501-004.test"
APPROVED_MARKER = "saf-0501-004-approved-fqdn-marker-8c21"
ALTERNATE_MARKER = "saf-0501-004-alternate-fqdn-marker-1a73"
FQDN_CLIENT_NS = "saf-0501-004-fqdn"
POLICY_NS_A = "saf-0501-004-selected-a"
POLICY_NS_B = "saf-0501-004-selected-b"
POLICY_NS_UNAFFECTED = "saf-0501-004-unaffected"
POLICY_CLIENT = "policy-observation-client"
WORLD_PORT = 8080

DNS_SERVER_CODE = r'''import socket, struct
records = {"''' + APPROVED_NAME + r'''.": "APPROVED_IP", "''' + ALTERNATE_NAME + r'''.": "ALTERNATE_IP"}
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 53))
while True:
    data, peer = s.recvfrom(2048)
    try:
        i = 12
        labels = []
        while data[i]:
            n = data[i]
            if n > 63:
                raise ValueError("Only uncompressed DNS questions are supported")
            i += 1
            labels.append(data[i:i+n].decode("ascii"))
            i += n
        qend = i + 5
        name = ".".join(labels).lower() + "."
        qtype, qclass = struct.unpack("!HH", data[i+1:i+5])
        question = data[12:qend]
        addr = records.get(name)
        answers = b""
        count = 0
        if addr and qtype == 1 and qclass == 1:
            octets = bytes(int(part) for part in addr.split("."))
            answers = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 5, 4) + octets
            count = 1
        header = data[:2] + struct.pack("!HHHHH", 0x8180, 1, count, 0, 0)
        s.sendto(header + question + answers, peer)
    except (IndexError, UnicodeError, ValueError, struct.error):
        pass
'''

SERVER_CODE = r'''from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def respond(self):
        body = b"''' + MARKER.encode().decode() + r'''"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_GET = respond
    do_POST = respond
    def log_message(self, fmt, *args):
        pass
HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''

PROBE_CODE = r'''import errno, json, sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import socket
url, method = sys.argv[1], sys.argv[2]
try:
    with urlopen(Request(url, method=method), timeout=4) as response:
        print(json.dumps({"status": response.status,
                          "body": response.read().decode("utf-8", "replace")}))
except HTTPError as error:
    print(json.dumps({"status": error.code,
                      "body": error.read().decode("utf-8", "replace")}))
except URLError as error:
    reason = error.reason
    code = getattr(reason, "errno", None)
    if isinstance(reason, (TimeoutError, socket.timeout)) or code == errno.ETIMEDOUT:
        kind = "TimeoutError"
    elif code in {errno.EHOSTUNREACH, errno.ENETUNREACH}:
        kind = "Unreachable"
    else:
        kind = "UnclassifiedNetworkError"
    print(json.dumps({"status": None, "error": kind}))
except OSError as error:
    code = getattr(error, "errno", None)
    kind = "TimeoutError" if code == errno.ETIMEDOUT else (
        "Unreachable" if code in {errno.EHOSTUNREACH, errno.ENETUNREACH}
        else "UnclassifiedNetworkError")
    print(json.dumps({"status": None, "error": kind}))
'''


def wait_pod(lab, name, namespace=NAMESPACE):
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=120s", timeout=130)
    pod_data = json.loads(lab.kubectl(
        "-n", namespace, "get", f"pod/{name}", "-o", "json").stdout)
    pod_ip = pod_data.get("status", {}).get("podIP")
    if not pod_ip:
        lab.block(f"Owned Pod {name} has no Pod IP")
    return pod_ip


def install_cilium(lab):
    kind_version = lab.command("kind", "version").stdout.strip()
    if not kind_version.startswith("kind v0.32.0"):
        lab.block(f"Expected pinned kind v0.32.0, got {kind_version}")
    server_version = json.loads(lab.kubectl("version", "-o", "json").stdout)[
        "serverVersion"]["gitVersion"]
    if server_version != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, got {server_version}")

    # kindnet remains active until the cluster and shared runner are Ready.
    # Helm then installs the pinned full Cilium CNI. cni.exclusive moves the
    # previous CNI config aside; only Pods created afterward are in this test.
    config_dir = lab.kubeconfig.parent
    registry = config_dir / "helm-registry.json"
    lab.command("helm", "pull", "oci://quay.io/cilium/charts/cilium",
                "--version", CILIUM_VERSION, "--destination", str(config_dir),
                "--registry-config", str(registry), timeout=120)
    chart = config_dir / f"cilium-{CILIUM_VERSION}.tgz"
    if sha256(chart.read_bytes()).hexdigest() != CILIUM_CHART_SHA256:
        lab.block("The pinned Cilium chart archive did not match the expected digest")
    lab.command(
        "helm", "upgrade", "--install", "cilium", str(chart),
        "--kubeconfig", str(lab.kubeconfig), "--kube-context", f"kind-{lab.cluster}",
        "--namespace", "kube-system", "--registry-config", str(registry),
        "--values", str(Path(__file__).with_name("cilium-values.yaml")),
        "--wait", "--timeout", "5m", timeout=320,
    )
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/cilium",
                "--timeout=240s", timeout=250)
    lab.kubectl("-n", "kube-system", "rollout", "status", "deployment/cilium-operator",
                "--timeout=240s", timeout=250)
    agent_data = json.loads(lab.kubectl(
        "-n", "kube-system", "get", "daemonset/cilium", "-o", "json").stdout)
    agent_images = [container["image"] for container in
                    agent_data["spec"]["template"]["spec"]["containers"]]
    if not any(f"cilium:v{CILIUM_VERSION}" in image for image in agent_images):
        lab.block(f"Cilium image is not pinned to v{CILIUM_VERSION}: {agent_images}")
    lab.kubectl("wait", "--for=condition=Ready", "nodes", "--all", "--timeout=120s",
                timeout=130)
    lab.check("positive", "Pinned Cilium CNI agents and operator are ready",
              True, {"kind": kind_version, "kubernetes": server_version,
                     "cilium_chart": CILIUM_VERSION, "agent_images": agent_images,
                     "node_readiness": "all Ready after Cilium install"})


def make_pod(name, labels, command, *, port=None, namespace=NAMESPACE,
             dns_nameserver=None, dns_port=None):
    container = {
        "name": "synthetic-http",
        "image": PYTHON_IMAGE,
        "imagePullPolicy": "IfNotPresent",
        "command": ["python", "-u", "-c", command],
        "securityContext": {"allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                            "runAsNonRoot": True, "runAsUser": 65532},
        "resources": {"requests": {"cpu": "10m", "memory": "64Mi"},
                      "limits": {"cpu": "250m", "memory": "128Mi"}},
    }
    if port:
        container["ports"] = [{"name": "http", "containerPort": port,
                                "protocol": "TCP"}]
        container["readinessProbe"] = {
            "tcpSocket": {"port": port}, "initialDelaySeconds": 1,
            "periodSeconds": 1, "failureThreshold": 20,
        }
    spec = {"automountServiceAccountToken": False,
            "restartPolicy": "Always", "containers": [container]}
    if dns_nameserver:
        spec.update(dnsPolicy="None", dnsConfig={
            "nameservers": [dns_nameserver], "options": [{"name": "ndots", "value": "1"}],
        })
    resource = {"apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": name, "namespace": namespace, "labels": labels},
                "spec": spec}
    if dns_port:
        container["ports"] = [{"name": "dns", "containerPort": dns_port,
                                "protocol": "UDP"}]
    return resource


def observe(lab, ip, method, client=CLIENT):
    result = lab.kubectl(
        "-n", NAMESPACE, "exec", f"pod/{client}", "--", "python", "-c",
        PROBE_CODE, f"http://{ip}:{PORT}/safe", method, timeout=15,
    )
    try:
        return json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        lab.block("Synthetic HTTP probe did not return its structured response")


def expect(lab, phase, claim, ip, method, status, body=None):
    deadline = time.monotonic() + 30
    actual = None
    while time.monotonic() < deadline:
        actual = observe(lab, ip, method)
        if actual.get("status") == status and (body is None or actual.get("body") == body):
            break
        time.sleep(0.5)
    lab.check(phase, claim,
              actual is not None and actual.get("status") == status
              and (body is None or actual.get("body") == body),
              {"method": method, "path": "/safe", "expected_status": status,
               "expected_marker": body, "observed": actual})


def pod_resource(name, namespace, labels, command, *, port=None, dns_nameserver=None,
                 dns_port=None):
    resource = make_pod(name, labels, command, port=port, namespace=namespace,
                        dns_nameserver=dns_nameserver, dns_port=dns_port)
    return resource


def run_dns_query(lab, name):
    code = (
        "import json,socket,sys; n=sys.argv[1].rstrip('.'); "
        "print(json.dumps({'name':sys.argv[1], 'ipv4':socket.gethostbyname(n)}))"
    )
    result = lab.kubectl("-n", FQDN_CLIENT_NS, "exec", f"pod/{CLIENT}", "--",
                         "python", "-c", code, name, timeout=15)
    try:
        return json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        lab.block("Owned DNS fixture query did not return a structured A record")


def is_network_block(observed):
    return observed.get("status") is None and observed.get("error") in {
        "TimeoutError", "Unreachable",
    }


def observe_until(lab, client, ip, method, predicate, timeout=30):
    deadline = time.monotonic() + timeout
    observed = None
    while time.monotonic() < deadline:
        observed = observe(lab, ip, method, client)
        if predicate(observed):
            return observed
        time.sleep(0.5)
    return observed


def run_native_networkpolicy_evidence(lab, server_ip):
    """Compare standard NetworkPolicy enforcement on owned Pods, then cleanly recover."""
    extra_client = "owned-http-unselected-client"
    resource_name = "native-selected-client-to-server"
    lab.kubectl("-n", NAMESPACE, "apply", "-f", "-", payload=json.dumps(make_pod(
        extra_client, {"app": extra_client}, "import time; time.sleep(3600)")))
    wait_pod(lab, extra_client)
    policy = {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": resource_name, "namespace": NAMESPACE},
        "spec": {
            "podSelector": {"matchLabels": {"app": SERVER}},
            "policyTypes": ["Ingress"],
            "ingress": [{
                "from": [{"podSelector": {"matchLabels": {"app": CLIENT}}}],
                "ports": [{"protocol": "TCP", "port": PORT}],
            }],
        },
    }
    cleanup_policy = False
    cleanup_pod = False
    selected_baseline = unselected_baseline = selected_get = selected_post = {}
    unselected_denied = unselected_recovered = {}
    policy_shape_matches = False
    try:
        selected_baseline = observe_until(
            lab, CLIENT, server_ip, "GET",
            lambda result: result.get("status") == 200 and result.get("body") == MARKER)
        unselected_baseline = observe_until(
            lab, extra_client, server_ip, "GET",
            lambda result: result.get("status") == 200 and result.get("body") == MARKER)
        lab.kubectl("-n", NAMESPACE, "apply", "-f", "-", payload=json.dumps(policy))
        readback = json.loads(lab.kubectl(
            "-n", NAMESPACE, "get", f"networkpolicy/{resource_name}", "-o", "json").stdout)
        policy_shape_matches = (
            readback.get("metadata", {}).get("name") == resource_name
            and readback.get("metadata", {}).get("namespace") == NAMESPACE
            and readback.get("spec") == policy["spec"]
        )
        selected_get = observe_until(
            lab, CLIENT, server_ip, "GET",
            lambda result: result.get("status") == 200 and result.get("body") == MARKER)
        selected_post = observe_until(
            lab, CLIENT, server_ip, "POST",
            lambda result: result.get("status") == 200 and result.get("body") == MARKER)
        unselected_denied = observe_until(
            lab, extra_client, server_ip, "GET", is_network_block)

        # Remove standard policy before the existing Cilium L7 policy is applied.
        lab.kubectl("-n", NAMESPACE, "delete", f"networkpolicy/{resource_name}",
                    "--wait=true", timeout=30)
        unselected_recovered = observe_until(
            lab, extra_client, server_ip, "GET",
            lambda result: result.get("status") == 200 and result.get("body") == MARKER)
    finally:
        cleanup_policy = lab.kubectl(
            "-n", NAMESPACE, "delete", f"networkpolicy/{resource_name}",
            "--ignore-not-found=true", allow_failure=True).returncode == 0
        cleanup_pod = lab.kubectl(
            "-n", NAMESPACE, "delete", f"pod/{extra_client}",
            "--ignore-not-found=true", "--wait=true", allow_failure=True).returncode == 0
    conditions = {
        "selected_baseline_marker": selected_baseline.get("status") == 200 and selected_baseline.get("body") == MARKER,
        "unselected_baseline_marker": unselected_baseline.get("status") == 200 and unselected_baseline.get("body") == MARKER,
        "policy_shape_matches": policy_shape_matches,
        "selected_get_marker": selected_get.get("status") == 200 and selected_get.get("body") == MARKER,
        "selected_post_marker": selected_post.get("status") == 200 and selected_post.get("body") == MARKER,
        "unselected_get_blocked": is_network_block(unselected_denied),
        "unselected_get_recovers_after_policy_removal": unselected_recovered.get("status") == 200 and unselected_recovered.get("body") == MARKER,
        "owned_policy_cleanup_succeeded": cleanup_policy,
        "owned_probe_cleanup_succeeded": cleanup_pod,
    }
    lab.check("positive", "Native NetworkPolicy selects the approved owned client, blocks the other, and recovers after cleanup",
              all(conditions.values()),
              {"namespace": NAMESPACE, "policy": resource_name,
               "selected_client": CLIENT, "unselected_client": extra_client,
               "destination": SERVER, "port": PORT,
               "conditions": conditions,
               "unselected_block_class": unselected_denied.get("error"),
               "policy_shape": "exact expected selector/protocol/port matched" if policy_shape_matches else "mismatch"})


OUTBOUND_HTTP_CODE = r'''import errno, json, sys
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, build_opener

opener = build_opener(ProxyHandler({}))
try:
    with opener.open("http://" + sys.argv[1] + ":" + sys.argv[2] + "/", timeout=3) as response:
        observed = {"status": response.status, "body": response.read(1024).decode("utf-8", "replace")}
except HTTPError as error:
    observed = {"status": error.code}
except (URLError, OSError) as error:
    cause = error.reason if isinstance(error, URLError) else error
    kind = "Unreachable" if getattr(cause, "errno", None) in {errno.EHOSTUNREACH, errno.ENETUNREACH} else type(cause).__name__
    observed = {"status": None, "error": kind}
print(json.dumps(observed))
'''


def outbound_http(lab, namespace, pod, host):
    result = lab.kubectl("-n", namespace, "exec", f"pod/{pod}", "--", "python", "-c",
                         OUTBOUND_HTTP_CODE, str(host), str(WORLD_PORT), timeout=15)
    try:
        return json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        lab.block("The owned outbound HTTP probe returned no structured observation")


def expect_named_http(lab, phase, claim, name, expected_status, expected_body=None):
    deadline = time.monotonic() + 30
    actual = None
    while time.monotonic() < deadline:
        actual = outbound_http(lab, FQDN_CLIENT_NS, CLIENT, name)
        matched = (is_network_block(actual) if expected_status is None
                   else actual.get("status") == expected_status)
        if matched and (
                expected_body is None or actual.get("body") == expected_body):
            break
        time.sleep(0.5)
    lab.check(phase, claim,
              actual is not None and (is_network_block(actual) if expected_status is None
                                      else actual.get("status") == expected_status)
              and (expected_body is None or actual.get("body") == expected_body),
              {"fqdn": name, "port": WORLD_PORT,
               "expected_status": expected_status, "expected_marker": expected_body,
               "observed": actual})


def expect_namespace_listener(lab, namespace, ip, marker):
    observed = outbound_http(lab, namespace, POLICY_CLIENT, ip)
    lab.check("positive", f"Targeted namespaced allow in {namespace} reaches owned listener",
              observed.get("status") == 200 and observed.get("body") == marker,
              {"namespace": namespace, "destination": "approved", "port": WORLD_PORT,
               "expected_marker": marker, "observed": observed})


def run_to_fqdns_evidence(lab, peer_ips):
    lab.kubectl("create", "namespace", FQDN_CLIENT_NS)
    dns_pod = pod_resource(DNS_FIXTURE, FQDN_CLIENT_NS, {"app": DNS_FIXTURE},
                          DNS_SERVER_CODE.replace("APPROVED_IP", str(peer_ips[0]))
                          .replace("ALTERNATE_IP", str(peer_ips[1])), dns_port=DNS_PORT)
    dns_container = dns_pod["spec"]["containers"][0]
    dns_container["securityContext"].update(runAsNonRoot=False, runAsUser=0,
                                             capabilities={"drop": ["ALL"],
                                                           "add": ["NET_BIND_SERVICE"]})
    lab.kubectl("-n", FQDN_CLIENT_NS, "apply", "-f", "-", payload=json.dumps(dns_pod))
    dns_ip = wait_pod(lab, DNS_FIXTURE, FQDN_CLIENT_NS)
    lab.kubectl("-n", FQDN_CLIENT_NS, "apply", "-f", "-",
                payload=json.dumps(pod_resource(
                    CLIENT, FQDN_CLIENT_NS, {"app": CLIENT}, "import time; time.sleep(3600)",
                    dns_nameserver=dns_ip)))
    wait_pod(lab, CLIENT, FQDN_CLIENT_NS)

    for name, ip, marker in ((APPROVED_NAME, str(peer_ips[0]), APPROVED_MARKER),
                             (ALTERNATE_NAME, str(peer_ips[1]), ALTERNATE_MARKER)):
        resolved = run_dns_query(lab, name)
        lab.check("red", f"Owned DNS fixture resolves {name} to its verified bridge IPv4",
                  resolved.get("ipv4") == ip,
                  {"fqdn": name, "expected_ipv4_matched": resolved.get("ipv4") == ip,
                   "resolver_source": "case-owned DNS Pod; DNS policy not yet applied"})
        observed = outbound_http(lab, FQDN_CLIENT_NS, CLIENT, name)
        lab.check("red", f"No-policy HTTP to {name} returns its fixed owned marker",
                  observed.get("status") == 200 and observed.get("body") == marker,
                  {"fqdn": name, "port": WORLD_PORT,
                   "expected_marker": marker, "observed": observed})

    fqdn_policy = {
        "apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
        "metadata": {"name": "selective-owned-test-fqdns", "namespace": FQDN_CLIENT_NS},
        "spec": {
            "description": "Allow DNS discovery for two owned names; allow HTTP only to the exact approved name.",
            "endpointSelector": {"matchLabels": {"app": CLIENT}},
            "egress": [
                {"toEndpoints": [{"matchLabels": {
                    "k8s:io.kubernetes.pod.namespace": FQDN_CLIENT_NS,
                    "k8s:app": DNS_FIXTURE,
                }}], "toPorts": [{"ports": [{"port": str(DNS_PORT), "protocol": "UDP"}],
                                "rules": {"dns": [{"matchName": APPROVED_NAME},
                                                    {"matchName": ALTERNATE_NAME}]}}]},
                {"toFQDNs": [{"matchName": APPROVED_NAME}],
                 "toPorts": [{"ports": [{"port": str(WORLD_PORT), "protocol": "TCP"}]}]},
            ],
        },
    }
    lab.kubectl("-n", FQDN_CLIENT_NS, "apply", "-f", "-",
                payload=json.dumps(fqdn_policy))

    approved_dns = run_dns_query(lab, APPROVED_NAME)
    lab.check("positive", "Selective DNS proxy permission preserves the approved exact A answer",
              approved_dns.get("ipv4") == str(peer_ips[0]),
              {"fqdn": APPROVED_NAME, "expected_ipv4_matched": approved_dns.get("ipv4") == str(peer_ips[0]),
               "dns_match_name": APPROVED_NAME})
    expect_named_http(lab, "positive", "toFQDNs permits the approved exact name and marker",
                      APPROVED_NAME, 200, APPROVED_MARKER)
    alternate_dns = run_dns_query(lab, ALTERNATE_NAME)
    lab.check("positive", "Selective DNS proxy permission preserves the alternate exact A answer",
              alternate_dns.get("ipv4") == str(peer_ips[1]),
              {"fqdn": ALTERNATE_NAME, "expected_ipv4_matched": alternate_dns.get("ipv4") == str(peer_ips[1]),
               "dns_match_name": ALTERNATE_NAME,
               "toFQDNs_match_name": APPROVED_NAME})
    expect_named_http(lab, "green", "DNS answer for the alternate name does not authorize its HTTP path",
                      ALTERNATE_NAME, None)
    alternate_dns_after_drop = run_dns_query(lab, ALTERNATE_NAME)
    lab.check("positive", "Alternate DNS answer remains available after its failed HTTP request",
              alternate_dns_after_drop.get("ipv4") == str(peer_ips[1]),
              {"fqdn": ALTERNATE_NAME,
               "expected_ipv4_matched": alternate_dns_after_drop.get("ipv4") == str(peer_ips[1]),
               "http_path_previously_failed": True})
    health = {}
    for name, marker in (("approved", APPROVED_MARKER), ("alternate", ALTERNATE_MARKER)):
        peer = f"{lab.cluster}-{name}-fqdn"
        result = lab.command("docker", "exec", peer, "wget", "-qO-",
                             f"http://127.0.0.1:{WORLD_PORT}/", allow_failure=True)
        health[name] = result.returncode == 0 and result.stdout.strip() == marker
    lab.check("positive", "Both external HTTP fixtures remain healthy after policy denial",
              all(health.values()), {"listener_health": health,
                                    "marker_by_role": {"approved": APPROVED_MARKER,
                                                       "alternate": ALTERNATE_MARKER}})


def run_clusterwide_policy_evidence(lab, approved_ip):
    namespaces = (POLICY_NS_A, POLICY_NS_B, POLICY_NS_UNAFFECTED)
    for namespace in namespaces:
        lab.kubectl("create", "namespace", namespace)
        lab.kubectl("-n", namespace, "apply", "-f", "-", payload=json.dumps(
            pod_resource(POLICY_CLIENT, namespace, {"app": POLICY_CLIENT},
                         "import time; time.sleep(3600)")))
        wait_pod(lab, POLICY_CLIENT, namespace)

    for namespace in namespaces[:2]:
        namespaced_allow = {
            "apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
            "metadata": {"name": "targeted-owned-http-allow", "namespace": namespace},
            "spec": {"endpointSelector": {"matchLabels": {"app": POLICY_CLIENT}},
                     "egress": [{"toCIDR": [f"{approved_ip}/32"],
                                 "toPorts": [{"ports": [{"port": str(WORLD_PORT),
                                                            "protocol": "TCP"}]}]}]},
        }
        lab.kubectl("-n", namespace, "apply", "-f", "-",
                    payload=json.dumps(namespaced_allow))
        expect_namespace_listener(lab, namespace, approved_ip, APPROVED_MARKER)

    global_deny = {
        "apiVersion": "cilium.io/v2", "kind": "CiliumClusterwideNetworkPolicy",
        "metadata": {"name": "deny-owned-http-in-two-selected-namespaces"},
        "spec": {
            "description": "Deny the same owned destination in exactly two selected namespaces.",
            "endpointSelector": {"matchLabels": {"app": POLICY_CLIENT},
                                 "matchExpressions": [{
                                     "key": "k8s:io.kubernetes.pod.namespace",
                                     "operator": "In", "values": [POLICY_NS_A, POLICY_NS_B]}]},
            "egressDeny": [{"toCIDR": [f"{approved_ip}/32"],
                            "toPorts": [{"ports": [{"port": str(WORLD_PORT),
                                                       "protocol": "TCP"}]}]}],
        },
    }
    lab.kubectl("apply", "-f", "-", payload=json.dumps(global_deny))
    for namespace in namespaces[:2]:
        deadline = time.monotonic() + 30
        consecutive = 0
        observed = None
        while time.monotonic() < deadline:
            observed = outbound_http(lab, namespace, POLICY_CLIENT, approved_ip)
            consecutive = consecutive + 1 if is_network_block(observed) else 0
            if consecutive == 2:
                break
            time.sleep(0.5)
        lab.check("green", f"Clusterwide deny overrides the targeted allow in {namespace}",
                  consecutive == 2 and is_network_block(observed),
                  {"namespace": namespace, "destination": "approved",
                   "port": WORLD_PORT, "namespaced_allow_present": True,
                   "clusterwide_deny_selected": True,
                   "two_consecutive_denied_observations": consecutive == 2,
                   "recognized_network_block": is_network_block(observed),
                   "observed": observed})
    deadline = time.monotonic() + 30
    consecutive = 0
    unaffected_observed = None
    while time.monotonic() < deadline:
        unaffected_observed = outbound_http(
            lab, POLICY_NS_UNAFFECTED, POLICY_CLIENT, approved_ip)
        allowed = (unaffected_observed.get("status") == 200
                   and unaffected_observed.get("body") == APPROVED_MARKER)
        consecutive = consecutive + 1 if allowed else 0
        if consecutive == 2:
            break
        time.sleep(0.5)
    lab.check("positive", "Clusterwide namespace selector leaves the third namespace unaffected",
              consecutive == 2,
              {"namespace": POLICY_NS_UNAFFECTED, "destination": "approved",
               "port": WORLD_PORT, "not_selected_by_clusterwide_deny": True,
               "two_consecutive_allowed_observations": consecutive == 2,
               "observed": unaffected_observed})


def run(lab):
    install_cilium(lab)
    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl("-n", NAMESPACE, "apply", "-f", "-", payload=json.dumps(make_pod(
        SERVER, {"app": SERVER}, SERVER_CODE, port=PORT)))
    lab.kubectl("-n", NAMESPACE, "apply", "-f", "-", payload=json.dumps(make_pod(
        CLIENT, {"app": CLIENT}, "import time; time.sleep(3600)")))
    server_ip = wait_pod(lab, SERVER)
    wait_pod(lab, CLIENT)

    # Both methods must reach the same owned listener before enforcement.
    expect(lab, "red", "Without Cilium policy, owned server returns its marker to GET",
           server_ip, "GET", 200, MARKER)
    expect(lab, "red", "Without Cilium policy, owned server returns its marker to POST",
           server_ip, "POST", 200, MARKER)

    run_native_networkpolicy_evidence(lab, server_ip)

    lab.kubectl("-n", NAMESPACE, "apply", "-f",
                str(Path(__file__).with_name("http-method-policy.yaml")))
    expect(lab, "positive", "Cilium allows the explicitly permitted GET /safe",
           server_ip, "GET", 200, MARKER)
    expect(lab, "green", "Cilium L7 policy rejects POST /safe with HTTP 403",
           server_ip, "POST", 403)

    run_owned_bridge_evidence(lab)


def run_owned_bridge_evidence(lab):
    network = f"{lab.cluster}-0501-004-fixtures"
    node = f"{lab.cluster}-control-plane"
    peers = (f"{lab.cluster}-approved-fqdn", f"{lab.cluster}-alternate-fqdn")
    connected = False
    network_created = False
    running = []
    lab.command("docker", "network", "create", "--internal", network)
    network_created = True
    try:
        lab.command("docker", "network", "connect", network, node)
        connected = True
        for role, name, marker in (("approved", peers[0], APPROVED_MARKER),
                                   ("alternate", peers[1], ALTERNATE_MARKER)):
            command = ("mkdir -p /tmp/www; printf %s " + shlex.quote(marker)
                       + " >/tmp/www/index.html; exec httpd -f -p "
                       + str(WORLD_PORT) + " -h /tmp/www")
            lab.command("docker", "run", "--rm", "--detach", "--name", name,
                        "--network", network, "--user=65534:65534", "--cap-drop=ALL",
                        "--security-opt=no-new-privileges", BUSYBOX_IMAGE,
                        "sh", "-ec", command)
            running.append(name)
        network_inspect = json.loads(lab.command(
            "docker", "network", "inspect", network).stdout)[0]
        if not network_inspect.get("Internal"):
            lab.block("External fixture Docker bridge is not marked internal")
        endpoint_names = sorted(item["Name"] for item in
                                network_inspect.get("Containers", {}).values())
        expected_names = sorted((node, *peers))
        lab.check("positive", "Disposable internal bridge contains only the runner node and two owned peers",
                  endpoint_names == expected_names,
                  {"internal": network_inspect.get("Internal"),
                   "attached_containers": len(endpoint_names), "all_owned": endpoint_names == expected_names})
        inspect = '{{(index .NetworkSettings.Networks "' + network + '").IPAddress}}'
        peer_ips = [lab.command("docker", "inspect", "--format", inspect, peer).stdout.strip()
                    for peer in peers]
        parsed_ips = [IPv4Address(value) for value in peer_ips]
        lab.check("positive", "Owned HTTP fixture peers have distinct verified IPv4 addresses",
                  parsed_ips[0] != parsed_ips[1],
                  {"expected_distinct_ipv4": parsed_ips[0] != parsed_ips[1]})
        for role, name, marker in zip(("approved", "alternate"), peers, (APPROVED_MARKER, ALTERNATE_MARKER)):
            deadline = time.monotonic() + 30
            healthy = False
            while time.monotonic() < deadline:
                result = lab.command("docker", "exec", name, "wget", "-qO-",
                                     f"http://127.0.0.1:{WORLD_PORT}/",
                                     allow_failure=True)
                if result.returncode == 0 and result.stdout.strip() == marker:
                    healthy = True
                    break
                time.sleep(0.5)
            lab.check("positive", f"Owned {role} HTTP fixture listener is healthy",
                      healthy, {"role": role, "port": WORLD_PORT,
                                "expected_marker": marker, "healthy": healthy})
        run_to_fqdns_evidence(lab, parsed_ips)
        run_clusterwide_policy_evidence(lab, parsed_ips[0])
    finally:
        cleanup_results = []
        for peer in running:
            cleanup_results.append(lab.command("docker", "rm", "--force", peer,
                                               allow_failure=True).returncode == 0)
        if connected:
            cleanup_results.append(lab.command("docker", "network", "disconnect", network, node,
                                               allow_failure=True).returncode == 0)
        if network_created:
            cleanup_results.append(lab.command("docker", "network", "rm", network,
                                               allow_failure=True).returncode == 0)
    lab.check("positive", "Owned external fixture containers and internal bridge are removed",
              all(cleanup_results), {"cleanup_commands_succeeded": cleanup_results,
                                     "external_fixture_containers": len(running),
                                     "network_was_internal": True})
