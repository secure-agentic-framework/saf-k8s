"""Exercise workload-scoped standard NetworkPolicy egress with synthetic peers."""
from ipaddress import IPv4Address
import json
from pathlib import Path
import time
from urllib.parse import urlsplit

from fixtures import BUSYBOX_IMAGE, container, pod


CLIENT_NS = "saf-0501-003-client"
SERVICES_NS = "saf-0501-003-services"
ROLE_LABEL = "saf-k8s.example/0501-003-role"
CLIENT = "case-client"
APPROVED = "approved-http"
RESTRICTED = "restricted-http"
PORT = 8080
MARKERS = {
    APPROVED: "saf-0501-003-approved-harmless-http-marker-91d2",
    RESTRICTED: "saf-0501-003-restricted-harmless-http-marker-47ac",
}
SCOPE = (
    "Kubernetes v1.36.1 kind with policy-capable bundled kindnet. A synthetic workload "
    "reaches two owned cluster HTTP listeners before egress enforcement. Namespace and Pod "
    "label allowances restore only the approved path. The same workload also contacts two "
    "owned HTTP peers on a separate Docker network outside Kubernetes. A real ipBlock /32 "
    "and port rule admits only the approved combination. Production IP authorities, "
    "FQDN policies, routing gateways and provider evidence remain separate."
)

def create(lab, namespace, resource):
    lab.kubectl("-n", namespace, "create", "-f", "-", payload=json.dumps(resource))


def verify_platform(lab):
    kind_version = lab.command("kind", "version").stdout.strip()
    version = json.loads(lab.kubectl("version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet",
                "--timeout=70s", timeout=80)
    dataplane = json.loads(lab.kubectl("-n", "kube-system", "get", "daemonset/kindnet", "-o", "json").stdout)
    images = [entry["image"] for entry in dataplane["spec"]["template"]["spec"]["containers"]]
    lab.check("positive", "Pinned local Kind and kindnet dataplane are ready",
              kind_version.startswith("kind v0.32.0") and version == "v1.36.1"
              and any("kindnetd" in image for image in images),
              {"kind_version": kind_version, "kubernetes_version": version, "cni_images": images})


def add_namespace(lab, namespace):
    lab.kubectl("create", "namespace", namespace)


def add_pod(lab, namespace, name, *, marker=None):
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
    workload["metadata"].update(namespace=namespace, labels={ROLE_LABEL: name})
    create(lab, namespace, workload)
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=90s", timeout=100)
    current = json.loads(lab.kubectl(
        "-n", namespace, "get", f"pod/{name}", "-o", "json").stdout)
    pod_ip = current.get("status", {}).get("podIP")
    if not pod_ip:
        lab.block(f"Case-owned Pod {namespace}/{name} has no Pod IP")
    if marker is not None:
        wait_local_listener(lab, namespace, name, marker)
    return pod_ip


def request(lab, url):
    result = lab.kubectl(
        "-n", CLIENT_NS, "exec", f"pod/{CLIENT}", "--", "wget", "-q", "-T", "2",
        "-O", "-", url, allow_failure=True, timeout=12,
    )
    if result.returncode == 0:
        return result.stdout.strip()
    error = (result.stdout + result.stderr).lower()
    if any(reason in error for reason in ("timed out", "connection refused", "no route to host", "network is unreachable")):
        return None
    lab.block("HTTP probe failed without a recognized network outcome")


def expect_http(lab, phase, claim, url, allowed, marker=None):
    deadline = time.monotonic() + 30
    consecutive = 0
    observed = None
    while time.monotonic() < deadline:
        body = request(lab, url)
        if body is not None and marker is not None and body != marker:
            lab.block("Owned HTTP listener returned an unexpected marker")
        observed = body is not None
        consecutive = consecutive + 1 if observed == allowed else 0
        if consecutive == 2:
            break
        time.sleep(0.5)
    lab.check(
        phase, claim, consecutive == 2,
        {"expected_reachable": allowed, "observed_reachable": observed,
         "two_consecutive_observations": consecutive == 2,
         "expected_fixed_marker": marker, "protocol": "IPv4 TCP", "port": urlsplit(url).port},
    )


def wait_local_listener(lab, namespace, pod_name, marker):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        result = lab.kubectl(
            "-n", namespace, "exec", f"pod/{pod_name}", "--", "wget", "-q", "-T", "2",
            "-O", "-", f"http://127.0.0.1:{PORT}/", allow_failure=True, timeout=12,
        )
        if result.returncode == 0:
            if result.stdout.strip() != marker:
                lab.block(f"Case-owned listener {namespace}/{pod_name} returned the wrong marker")
            return
        time.sleep(0.5)
    lab.block(f"Case-owned HTTP listener {namespace}/{pod_name} did not become healthy")


def run(lab):
    verify_platform(lab)
    lab.kubectl("create", "namespace", CLIENT_NS)
    lab.kubectl("create", "namespace", SERVICES_NS)
    approved_ip = add_pod(lab, SERVICES_NS, APPROVED, marker=MARKERS[APPROVED])
    restricted_ip = add_pod(lab, SERVICES_NS, RESTRICTED, marker=MARKERS[RESTRICTED])
    add_pod(lab, CLIENT_NS, CLIENT)

    check_external_endpoints(lab)

    # The same owned endpoints must be reachable before any egress policy exists.
    expect_http(lab, "red", "No-policy client reaches the approved owned listener",
                f"http://{approved_ip}:{PORT}/", True, MARKERS[APPROVED])
    expect_http(lab, "red", "No-policy client reaches the restricted owned listener",
                f"http://{restricted_ip}:{PORT}/", True, MARKERS[RESTRICTED])

    lab.kubectl("-n", CLIENT_NS, "apply", "-f",
                str(Path(__file__).with_name("network-policy.yaml")))
    expect_http(lab, "green", "Client-only egress default deny blocks the approved listener",
                f"http://{approved_ip}:{PORT}/", False)
    expect_http(lab, "green", "Client-only egress default deny blocks the restricted listener",
                f"http://{restricted_ip}:{PORT}/", False)

    lab.kubectl("-n", CLIENT_NS, "apply", "-f",
                str(Path(__file__).with_name("approved-http-allow.yaml")))
    expect_http(lab, "positive", "Scoped egress allows the approved listener exact marker",
                f"http://{approved_ip}:{PORT}/", True, MARKERS[APPROVED])
    expect_http(lab, "green", "Scoped egress continues to deny the restricted listener",
                f"http://{restricted_ip}:{PORT}/", False)

    for name, marker in ((APPROVED, MARKERS[APPROVED]), (RESTRICTED, MARKERS[RESTRICTED])):
        wait_local_listener(lab, SERVICES_NS, name, marker)
    lab.check("positive", "Both synthetic listeners stay healthy during egress denial",
              True, {"approved_listener": True, "restricted_listener": True,
                     "listener_markers": list(MARKERS.values())})



def check_external_endpoints(lab):
    network = f"{lab.cluster}-egress-peers"
    node = f"{lab.cluster}-control-plane"
    peers = []
    connected = False
    policy = "case-exact-external-ip-port"
    policy_created = False
    lab.command("docker", "network", "create", network)
    try:
        lab.command("docker", "network", "connect", network, node)
        connected = True
        for role in ("approved", "restricted"):
            name = f"{lab.cluster}-{role}-egress"
            command = (
                f"mkdir -p /tmp/primary /tmp/alternate; "
                f"printf %s 'owned-{role}-8080' >/tmp/primary/index.html; "
                f"printf %s 'owned-{role}-8081' >/tmp/alternate/index.html; "
                "httpd -p 8080 -h /tmp/primary; exec httpd -f -p 8081 -h /tmp/alternate"
            )
            lab.command("docker", "run", "--rm", "--detach", "--name", name, "--network", network,
                        "--user=65534:65534", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                        BUSYBOX_IMAGE, "sh", "-ec", command)
            peers.append(name)
        inspect = '{{(index .NetworkSettings.Networks "' + network + '").IPAddress}}'
        approved_ip, restricted_ip = (
            IPv4Address(lab.command("docker", "inspect", "--format", inspect, name).stdout.strip()) for name in peers
        )
        intended = f"http://{approved_ip}:8080/"
        wrong_port = f"http://{approved_ip}:8081/"
        wrong_address = f"http://{restricted_ip}:8080/"
        for label, url, marker in (
            ("approved address and port", intended, "owned-approved-8080"),
            ("same address at the alternate port", wrong_port, "owned-approved-8081"),
            ("alternate address at the approved port", wrong_address, "owned-restricted-8080"),
        ):
            expect_http(lab, "red", f"Without egress enforcement the client reaches the owned {label}", url, True, marker)
        create(lab, CLIENT_NS, {
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": policy, "namespace": CLIENT_NS},
            "spec": {"podSelector": {"matchLabels": {ROLE_LABEL: CLIENT}},
                     "policyTypes": ["Egress"], "egress": [{
                         "to": [{"ipBlock": {"cidr": f"{approved_ip}/32"}}],
                         "ports": [{"protocol": "TCP", "port": 8080}],
                     }]},
        })
        policy_created = True
        expect_http(lab, "green", "The /32 egress rule denies the exact alternate address",
                    wrong_address, False, "owned-restricted-8080")
        expect_http(lab, "green", "The port rule denies the alternate port on the approved address",
                    wrong_port, False, "owned-approved-8081")
        expect_http(lab, "positive", "The exact approved external address and port still return their marker",
                    intended, True, "owned-approved-8080")
        live = all(lab.command("docker", "exec", name, "wget", "-qO-", f"http://127.0.0.1:{port}/").stdout.strip()
                   == f"owned-{role}-{port}"
                   for name, role, port in ((peers[0], "approved", 8081), (peers[1], "restricted", 8080)))
        lab.check("positive", "Both externally located denied paths have healthy owned listeners",
                  live, {"listeners_responded_locally": live})
    finally:
        if policy_created:
            lab.kubectl("-n", CLIENT_NS, "delete", "networkpolicy", policy)
        for name in peers:
            lab.command("docker", "rm", "--force", name)
        if connected:
            lab.command("docker", "network", "disconnect", network, node)
        lab.command("docker", "network", "rm", network)
    lab.check("positive", "The isolated external endpoint network and peers are removed",
              True, {"external_network_removed": True, "external_peers_removed": len(peers)})
