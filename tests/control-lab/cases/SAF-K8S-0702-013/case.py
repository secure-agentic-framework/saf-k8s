"""Exercise the kindnet policy dataplane with case-owned HTTP fixtures."""
import ipaddress
import json
import time

from fixtures import container, pod


TENANT_A = "saf-0702-013-a"
TENANT_B = "saf-0702-013-b"
REVIEWER = "saf-0702-013-peer"
APP = "saf-k8s.example/fixture"
PORT = 8080
MARKER = "saf-networkpolicy-static-fixture"
SCOPE = (
    "Two case-owned kind v1.36.1 nodes, stock policy-capable kindnet, IPv4 TCP only. "
    "A fixed HTTP marker from fixture Pod IPs verifies isolated tenant egress and ingress "
    "independently, plus a joint allow and denied source and destination controls. No "
    "external network, DNS, host-network, production CNI or institutional review is tested."
)


def create(lab, resource):
    namespace = resource["metadata"]["namespace"]
    lab.kubectl("-n", namespace, "create", "-f", "-", payload=json.dumps(resource))


def fixture(lab, namespace, name, node, *, server=False):
    if server:
        command = ["sh", "-ec",
                   f"printf %s {MARKER} >/tmp/index.html; exec httpd -f -p {PORT} -h /tmp"]
    else:
        command = ["sleep", "900"]
    workload = pod(
        name, [container("fixture", command=command)],
        automountServiceAccountToken=False,
        nodeSelector={"kubernetes.io/hostname": node},
        tolerations=[{"key": "node-role.kubernetes.io/control-plane", "operator": "Exists",
                      "effect": "NoSchedule"}],
    )
    workload["metadata"].update(namespace=namespace, labels={APP: name})
    create(lab, workload)
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=90s", timeout=100)
    current = json.loads(lab.kubectl("-n", namespace, "get", f"pod/{name}", "-o", "json").stdout)
    if current["spec"]["nodeName"] != node or ipaddress.ip_address(current["status"]["podIP"]).version != 4:
        lab.block("Fixture Pod is outside the expected owned IPv4 node")
    return current["status"]["podIP"]


def policy(lab, namespace, name, types, pods=None, **rules):
    create(lab, {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"podSelector": pods or {}, "policyTypes": types, **rules},
    })


def selector(name):
    return {"matchLabels": {APP: name}}


def peer(namespace, name):
    return {
        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": namespace}},
        "podSelector": selector(name),
    }


def connection(lab, source_namespace, client, server_ip):
    result = lab.kubectl(
        "-n", source_namespace, "exec", f"pod/{client}", "--",
        "wget", "-q", "-T", "2", "-O", "-", f"http://{server_ip}:{PORT}/",
        allow_failure=True, timeout=12,
    )
    if result.returncode == 0:
        if result.stdout.strip() != MARKER:
            lab.block("Fixture HTTP request returned an unexpected body")
        return True
    if "wget:" in result.stderr and any(message in result.stderr.lower() for message in (
            "timed out", "connection refused", "no route to host")):
        return False
    lab.block("Connectivity probe did not execute or return a network outcome")


def expect_path(lab, phase, wording, namespace, client, address, allowed):
    deadline = time.monotonic() + 30
    seen = 0
    while True:
        outcome = connection(lab, namespace, client, address)
        seen = seen + 1 if outcome == allowed else 0
        if seen == 2 or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check(phase, wording, seen == 2,
              {"expected_reachable": allowed, "observed_reachable": outcome,
               "two_consecutive_observations": seen == 2})


def run(lab):
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet",
                "--timeout=60s", timeout=70)
    for namespace in (TENANT_A, TENANT_B, REVIEWER):
        lab.kubectl("create", "namespace", namespace)
    source, destination = f"{lab.cluster}-control-plane", f"{lab.cluster}-worker"
    fixture(lab, TENANT_A, "approved-client", source)
    fixture(lab, TENANT_A, "other-client", source)
    fixture(lab, REVIEWER, "peer-client", source)
    server = fixture(lab, TENANT_B, "approved-server", destination, server=True)
    unrelated = fixture(lab, TENANT_B, "other-server", destination, server=True)
    paths = [
        (TENANT_A, "approved-client", server),
        (TENANT_A, "other-client", server),
        (REVIEWER, "peer-client", server),
        (TENANT_A, "approved-client", unrelated),
    ]
    for namespace, client, address in paths:
        target = "other-server" if address == unrelated else "approved-server"
        expect_path(lab, "red", f"Before policy, {client} reaches {target} across nodes",
                    namespace, client, address, True)

    ports = [{"protocol": "TCP", "port": PORT}]
    policy(lab, TENANT_A, "tenant-default-deny", ["Ingress", "Egress"])
    expect_path(lab, "green", "The source tenant's default deny blocks egress independently",
                TENANT_A, "approved-client", server, False)
    expect_path(lab, "positive", "An unisolated peer still reaches the server",
                REVIEWER, "peer-client", server, True)
    policy(lab, TENANT_A, "approved-egress", ["Egress"], selector("approved-client"),
           egress=[{"to": [peer(TENANT_B, "approved-server")], "ports": ports}])
    expect_path(lab, "positive", "Exact egress allow restores connectivity before ingress isolation",
                TENANT_A, "approved-client", server, True)

    policy(lab, TENANT_B, "tenant-default-deny", ["Ingress", "Egress"])
    expect_path(lab, "green", "The destination tenant's default deny blocks ingress independently",
                TENANT_A, "approved-client", server, False)
    policy(lab, TENANT_B, "approved-ingress", ["Ingress"], selector("approved-server"),
           ingress=[{"from": [peer(TENANT_A, "approved-client")], "ports": ports}])
    expect_path(lab, "positive", "Both exact policies admit the approved cross-tenant path",
                TENANT_A, "approved-client", server, True)
    expect_path(lab, "green", "An unapproved client Pod remains denied",
                TENANT_A, "other-client", server, False)
    expect_path(lab, "green", "An unapproved namespace remains denied at ingress",
                REVIEWER, "peer-client", server, False)
    expect_path(lab, "green", "An unapproved destination Pod remains denied",
                TENANT_A, "approved-client", unrelated, False)
