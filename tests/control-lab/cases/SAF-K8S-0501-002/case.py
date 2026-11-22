"""Exercise cross-namespace NetworkPolicy isolation and scoped exceptions."""
import json
import re
from pathlib import Path
import time

from fixtures import container, pod


TRUSTED_NS = "saf-0501-002-trusted"
UNTRUSTED_NS = "saf-0501-002-untrusted"
PROTECTED_NS = "saf-0501-002-protected"
TRUSTED_NAMESPACE_LABEL = "saf-k8s.example/0501-002-client-domain"
ROLE_LABEL = "saf-k8s.example/0501-002-role"
TRUSTED_CLIENT = "approved-client"
WRONG_POD_CLIENT = "wrong-pod-client"
WRONG_NAMESPACE_CLIENT = "wrong-namespace-client"
APPROVED_SERVER = "approved-http"
RESTRICTED_SERVER = "restricted-http"
PORT = 8080
MARKERS = {
    APPROVED_SERVER: "saf-0501-002-approved-marker-4f91",
    RESTRICTED_SERVER: "saf-0501-002-restricted-marker-2a73",
}
SERVICE = "approved-http"
SERVICE_FQDN = f"{SERVICE}.{PROTECTED_NS}.svc.cluster.local"
SCOPE = (
    "One disposable kind v0.32.0 cluster on the lab runner's digest-pinned Kubernetes "
    "v1.36.1 node image, using the ready bundled kindnet daemonset. Three case-owned "
    "namespaces contain three source Pods and two HTTP marker Pods; IPv4 TCP/8080 probes "
    "compare no-policy baseline with ingress isolation, namespaceSelector+podSelector "
    "conjunction, and one explicit source-to-approved-Service flow. A DNS phase checks the "
    "owned Service through the in-cluster "
    "kube-dns Service and CoreDNS endpoints, with client egress restricted to CoreDNS UDP/TCP "
    "53 before a separate TCP/8080 application allowance. No external targets, scans, "
    "production CNI, monitoring flows, IPv6, hostNetwork/node paths, or admission/generation "
    "automation is tested."
)


def create(lab, namespace, resource):
    lab.kubectl("-n", namespace, "create", "-f", "-", payload=json.dumps(resource))


def add_namespace(lab, namespace, *, trusted=False):
    lab.kubectl("create", "namespace", namespace)
    if trusted:
        lab.kubectl("label", "namespace", namespace, f"{TRUSTED_NAMESPACE_LABEL}=approved")


def add_pod(lab, namespace, name, role, *, marker=None):
    command = ["sleep", "900"]
    if marker is not None:
        command = [
            "sh", "-ec",
            f"printf %s {marker} >/tmp/index.html; exec httpd -f -p {PORT} -h /tmp",
        ]
    workload = pod(
        name,
        [container("fixture", command=command)],
        automountServiceAccountToken=False,
    )
    workload["metadata"].update(namespace=namespace, labels={ROLE_LABEL: role})
    create(lab, namespace, workload)
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=90s", timeout=100)
    current = json.loads(lab.kubectl("-n", namespace, "get", f"pod/{name}", "-o", "json").stdout)
    if not current.get("status", {}).get("podIP"):
        lab.block(f"Case-owned Pod {namespace}/{name} has no Pod IP")
    if marker is not None:
        wait_local_listener(lab, namespace, name, marker)
    return current["status"]["podIP"]


def request(lab, namespace, client, url, expected_marker):
    result = lab.kubectl(
        "-n", namespace, "exec", f"pod/{client}", "--", "wget", "-q", "-T", "2",
        "-O", "-", url, allow_failure=True, timeout=12,
    )
    if result.returncode == 0:
        if result.stdout.strip() != expected_marker:
            lab.block("HTTP probe reached a listener but returned the wrong fixed marker")
        return True
    combined = (result.stdout + result.stderr).lower()
    if any(reason in combined for reason in (
            "timed out", "connection refused", "can't connect", "no route to host",
            "network is unreachable", "operation timed out")):
        return False
    lab.block(f"HTTP probe failed without a recognized network outcome: {combined.strip()!r}")


def expect_http(lab, phase, claim, namespace, client, url, marker, allowed):
    deadline = time.monotonic() + 30
    consecutive = 0
    last = None
    while time.monotonic() < deadline:
        last = request(lab, namespace, client, url, marker)
        consecutive = consecutive + 1 if last == allowed else 0
        if consecutive == 2:
            break
        time.sleep(0.5)
    lab.check(
        phase, claim, consecutive == 2,
        {"expected_reachable": allowed, "observed_reachable": last,
         "two_consecutive_observations": consecutive == 2, "source_namespace": namespace, "source_pod": client,
         "owned_destination_marker": marker, "service_dns_path": SERVICE_FQDN in url,
         "protocol": "IPv4 TCP", "destination_port": PORT},
    )


def wait_local_listener(lab, namespace, name, marker):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        result = lab.kubectl(
            "-n", namespace, "exec", f"pod/{name}", "--", "wget", "-q", "-T", "2",
            "-O", "-", f"http://127.0.0.1:{PORT}/", allow_failure=True, timeout=12,
        )
        if result.returncode == 0:
            if result.stdout.strip() != marker:
                lab.block(f"Case-owned listener {namespace}/{name} returned the wrong marker")
            return
        time.sleep(0.5)
    lab.block(f"Case-owned HTTP listener {namespace}/{name} did not become healthy")


def service():
    return {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": SERVICE, "namespace": PROTECTED_NS},
        "spec": {
            "type": "ClusterIP",
            "selector": {ROLE_LABEL: APPROVED_SERVER},
            "ports": [{"name": "http", "protocol": "TCP", "port": PORT,
                       "targetPort": PORT}],
        },
    }


def resolve_owned_service(lab, namespace, client, expected_cluster_ip):
    result = lab.kubectl(
        "-n", namespace, "exec", f"pod/{client}", "--", "nslookup",
        "-timeout=1", "-retry=1", SERVICE_FQDN, allow_failure=True, timeout=12,
    )
    output = result.stdout + result.stderr
    addresses = re.findall(r"^Address(?:es)?(?: [0-9]+)?:\s+(\S+)", output, flags=re.MULTILINE)
    return result.returncode == 0 and expected_cluster_ip in addresses


def expect_dns(lab, phase, claim, expected_resolves, cluster_ip):
    deadline = time.monotonic() + 30
    consecutive = 0
    while time.monotonic() < deadline and consecutive < 2:
        resolves = resolve_owned_service(lab, TRUSTED_NS, TRUSTED_CLIENT, cluster_ip)
        consecutive = consecutive + 1 if resolves == expected_resolves else 0
        if consecutive < 2:
            time.sleep(0.5)
    lab.check(
        phase, claim, consecutive == 2,
        {"expected_resolves": expected_resolves, "expected_cluster_ip_received": resolves,
         "service_fqdn": SERVICE_FQDN, "two_consecutive_observations": consecutive == 2},
    )


def verify_platform_and_dns(lab):
    kind_version = lab.command("kind", "version").stdout.strip()
    if not kind_version.startswith("kind v0.32.0"):
        lab.block(f"Expected policy-capable kind v0.32.0, got {kind_version!r}")
    server = json.loads(lab.kubectl("version", "-o", "json").stdout).get("serverVersion", {})
    if server.get("gitVersion") != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, got {server.get('gitVersion')!r}")
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet",
                "--timeout=60s", timeout=70)
    kindnet = json.loads(lab.kubectl(
        "-n", "kube-system", "get", "daemonset", "kindnet", "-o", "json").stdout)
    images = [container["image"] for container in kindnet["spec"]["template"]["spec"]["containers"]]
    lab.check(
        "positive", "Pinned kind version and ready bundled kindnet are identified",
        any("kindnetd" in image for image in images),
        {"kind_version": kind_version, "kubernetes_version": server.get("gitVersion"),
         "cni_daemonset": "kube-system/kindnet", "cni_images": images},
    )

    dns_service = json.loads(lab.kubectl(
        "-n", "kube-system", "get", "service", "kube-dns", "-o", "json").stdout)
    cluster_ip = dns_service.get("spec", {}).get("clusterIP")
    dns_selector = dns_service.get("spec", {}).get("selector", {})
    service_ports = dns_service.get("spec", {}).get("ports", [])
    has_udp = any(port.get("port") == 53 and port.get("protocol") == "UDP" for port in service_ports)
    has_tcp = any(port.get("port") == 53 and port.get("protocol") == "TCP" for port in service_ports)
    lab.kubectl("-n", "kube-system", "wait", "--for=condition=Ready", "pod",
                "-l", "k8s-app=kube-dns", "--timeout=50s", timeout=55)
    dns_pods = json.loads(lab.kubectl(
        "-n", "kube-system", "get", "pods", "-l", "k8s-app=kube-dns", "-o", "json").stdout)
    ready_dns_pods = [
        item for item in dns_pods.get("items", [])
        if item.get("status", {}).get("phase") == "Running"
        and any(condition.get("type") == "Ready" and condition.get("status") == "True"
                for condition in item.get("status", {}).get("conditions", []))
    ]
    slices = json.loads(lab.kubectl(
        "-n", "kube-system", "get", "endpointslices",
        "-l", "kubernetes.io/service-name=kube-dns", "-o", "json").stdout)
    ready_endpoints = [
        endpoint for item in slices.get("items", [])
        for endpoint in item.get("endpoints", [])
        if endpoint.get("conditions", {}).get("ready") is True
    ]
    if (not cluster_ip or cluster_ip == "None" or not has_udp or not has_tcp
            or dns_selector.get("k8s-app") != "kube-dns"
            or not ready_dns_pods or not ready_endpoints):
        lab.block("Owned-Service DNS evidence requires ready kube-dns UDP/TCP 53 endpoints")
    lab.check(
        "positive", "In-cluster kube-dns Service has ready CoreDNS endpoints and UDP/TCP 53",
        True,
        {"service": "kube-system/kube-dns", "service_cluster_ip_present": bool(cluster_ip),
         "udp_53": has_udp, "tcp_53": has_tcp,
         "service_selector": dns_selector,
         "has_ready_pods": bool(ready_dns_pods), "has_ready_endpoints": bool(ready_endpoints)},
    )
    return cluster_ip


def run(lab):
    verify_platform_and_dns(lab)
    add_namespace(lab, TRUSTED_NS, trusted=True)
    add_namespace(lab, UNTRUSTED_NS)
    add_namespace(lab, PROTECTED_NS)

    approved_ip = add_pod(lab, PROTECTED_NS, APPROVED_SERVER, APPROVED_SERVER,
                          marker=MARKERS[APPROVED_SERVER])
    restricted_ip = add_pod(lab, PROTECTED_NS, RESTRICTED_SERVER, RESTRICTED_SERVER,
                            marker=MARKERS[RESTRICTED_SERVER])
    add_pod(lab, TRUSTED_NS, TRUSTED_CLIENT, TRUSTED_CLIENT)
    add_pod(lab, TRUSTED_NS, WRONG_POD_CLIENT, "wrong-client")
    add_pod(lab, UNTRUSTED_NS, WRONG_NAMESPACE_CLIENT, TRUSTED_CLIENT)
    create(lab, PROTECTED_NS, service())
    svc = json.loads(lab.kubectl(
        "-n", PROTECTED_NS, "get", "service", SERVICE, "-o", "json").stdout)
    service_ip = svc.get("spec", {}).get("clusterIP")
    if not service_ip or service_ip == "None":
        lab.block("Case-owned approved HTTP Service has no ClusterIP")

    # Prove every exact path and the Service DNS name are healthy before policy.
    for namespace, client in (
            (TRUSTED_NS, TRUSTED_CLIENT), (TRUSTED_NS, WRONG_POD_CLIENT),
            (UNTRUSTED_NS, WRONG_NAMESPACE_CLIENT)):
        expect_http(lab, "red", "Without policy, source reaches approved owned marker",
                    namespace, client, f"http://{approved_ip}:{PORT}/",
                    MARKERS[APPROVED_SERVER], True)
        expect_http(lab, "red", "Without policy, source reaches restricted owned marker",
                    namespace, client, f"http://{restricted_ip}:{PORT}/",
                    MARKERS[RESTRICTED_SERVER], True)
    expect_dns(lab, "red", "Without egress policy, actual cluster DNS resolves the owned Service",
               True, service_ip)
    expect_http(lab, "red", "Without policy, owned Service DNS routes to its exact marker",
                TRUSTED_NS, TRUSTED_CLIENT, f"http://{SERVICE_FQDN}:{PORT}/",
                MARKERS[APPROVED_SERVER], True)

    # A single NetworkPolicyPeer contains both selectors, so they are conjunctive.
    lab.kubectl("-n", PROTECTED_NS, "apply", "-f", str(Path(__file__).with_name("network-policy.yaml")))
    expect_http(lab, "positive", "Matching namespace and pod labels permit the approved cross-namespace flow",
                TRUSTED_NS, TRUSTED_CLIENT, f"http://{approved_ip}:{PORT}/",
                MARKERS[APPROVED_SERVER], True)
    expect_http(lab, "green", "Wrong pod label in the approved namespace is denied",
                TRUSTED_NS, WRONG_POD_CLIENT, f"http://{approved_ip}:{PORT}/",
                MARKERS[APPROVED_SERVER], False)
    expect_http(lab, "green", "Matching pod label in an unapproved namespace is denied",
                UNTRUSTED_NS, WRONG_NAMESPACE_CLIENT, f"http://{approved_ip}:{PORT}/",
                MARKERS[APPROVED_SERVER], False)
    expect_http(lab, "green", "Default ingress isolation denies the second owned marker",
                TRUSTED_NS, TRUSTED_CLIENT, f"http://{restricted_ip}:{PORT}/",
                MARKERS[RESTRICTED_SERVER], False)

    # Isolate only the approved source so the ingress selector probes above remain independent.
    lab.kubectl("-n", TRUSTED_NS, "apply", "-f", str(Path(__file__).with_name("client-egress-default-deny.yaml")))
    expect_dns(lab, "green", "Client egress default deny blocks DNS before a DNS exception",
               False, service_ip)
    lab.kubectl("-n", TRUSTED_NS, "apply", "-f", str(Path(__file__).with_name("client-dns-allow.yaml")))
    expect_dns(lab, "positive", "Narrow CoreDNS UDP/TCP 53 allowance restores owned-Service DNS",
               True, service_ip)
    expect_http(lab, "green", "DNS allowance alone does not open the application port",
                TRUSTED_NS, TRUSTED_CLIENT, f"http://{SERVICE_FQDN}:{PORT}/",
                MARKERS[APPROVED_SERVER], False)
    lab.kubectl("-n", TRUSTED_NS, "apply", "-f", str(Path(__file__).with_name("client-service-allow.yaml")))
    expect_http(lab, "positive", "Separate scoped egress allowance preserves owned Service HTTP by DNS name",
                TRUSTED_NS, TRUSTED_CLIENT, f"http://{SERVICE_FQDN}:{PORT}/",
                MARKERS[APPROVED_SERVER], True)

    for name, marker in MARKERS.items():
        wait_local_listener(lab, PROTECTED_NS, name, marker)
    lab.check("positive", "Both owned HTTP listeners remain locally healthy during policy denial",
              True, {"approved_and_restricted_listeners_healthy": True,
                     "markers": list(MARKERS.values())})
