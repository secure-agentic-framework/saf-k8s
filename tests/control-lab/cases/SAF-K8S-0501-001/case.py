"""Exercise namespace-wide ingress and egress NetworkPolicy enforcement."""
import json
from pathlib import Path
import time

from fixtures import container, pod


NAMESPACE = "saf-0501-001"
APP = "saf-k8s.example/0501-001"
PORT = 8080
CLIENT = "case-client"
APPROVED = "approved-http"
UNAPPROVED = "unapproved-http"
MARKERS = {
    APPROVED: "saf-0501-001-approved-fixed-marker",
    UNAPPROVED: "saf-0501-001-unapproved-fixed-marker",
}
SCOPE = (
    "One disposable kind v1.36.1 cluster with kind v0.32.0 bundled kindnet and one case-owned "
    "namespace. Three non-root BusyBox Pods provide one client and two fixed HTTP listeners; "
    "ordinary IPv4 TCP/8080 requests establish no-policy reachability, ingress-only denial, "
    "egress-only denial, and a joint namespace-wide default-deny policy with one explicit "
    "client-to-approved-listener allow path. No external targets, DNS, IPv6, other protocols, "
    "production CNI, system namespaces, hostNetwork/node paths, or admission/generation "
    "automation is tested."
)


def create(lab, resource):
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(resource))


def selector(pod_name):
    return {"matchLabels": {APP: pod_name}}


def network_policy(name, pod_selector, policy_types, **rules):
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": {"podSelector": pod_selector, "policyTypes": policy_types, **rules},
    }


def add_pod(lab, name, *, marker=None):
    if marker:
        command = [
            "sh", "-ec",
            f"printf %s {marker} >/tmp/index.html; exec httpd -f -p {PORT} -h /tmp",
        ]
    else:
        command = ["sleep", "900"]
    workload = pod(
        name,
        [container("fixture", command=command)],
        automountServiceAccountToken=False,
    )
    workload["metadata"].update(namespace=NAMESPACE, labels={APP: name})
    create(lab, workload)
    lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=90s", timeout=100)
    current = json.loads(lab.kubectl("-n", NAMESPACE, "get", f"pod/{name}", "-o", "json").stdout)
    if not current.get("status", {}).get("podIP"):
        lab.block(f"Case-owned Pod {name} has no Pod IP")
    return current["status"]["podIP"]


def request(lab, destination_ip, expected_marker, client=CLIENT):
    result = lab.kubectl(
        "-n", NAMESPACE, "exec", f"pod/{client}", "--", "wget", "-q", "-T", "2",
        "-O", "-", f"http://{destination_ip}:{PORT}/", allow_failure=True, timeout=12,
    )
    if result.returncode == 0:
        if result.stdout.strip() != expected_marker:
            lab.block("HTTP probe reached a listener but returned the wrong fixed marker")
        return True
    combined = (result.stdout + result.stderr).lower()
    if any(reason in combined for reason in (
            "timed out", "connection refused", "no route to host", "network is unreachable")):
        return False
    lab.block("HTTP probe failed without a recognized network outcome")


def expect_path(lab, phase, destination_ip, marker, allowed, claim):
    deadline = time.monotonic() + 30
    consecutive = 0
    observed = None
    while time.monotonic() < deadline:
        observed = request(lab, destination_ip, marker)
        consecutive = consecutive + 1 if observed == allowed else 0
        if consecutive == 2:
            break
        time.sleep(0.5)
    lab.check(
        phase, claim, consecutive == 2,
        {"expected_reachable": allowed, "observed_reachable": observed,
         "two_consecutive_observations": consecutive == 2, "protocol": "IPv4 TCP",
         "destination_port": PORT},
    )


def delete_policy(lab, name):
    lab.kubectl("-n", NAMESPACE, "delete", "networkpolicy", name, "--wait=true")


def check_platform(lab):
    kind_version = lab.command("kind", "version").stdout.strip()
    if not kind_version.startswith("kind v0.32.0"):
        lab.block(f"Expected kind v0.32.0 with bundled policy-capable kindnet, got {kind_version!r}")
    server = json.loads(lab.kubectl("version", "-o", "json").stdout).get("serverVersion", {})
    if server.get("gitVersion") != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, got {server.get('gitVersion')!r}")
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet",
                "--timeout=60s", timeout=70)
    net = json.loads(lab.kubectl(
        "-n", "kube-system", "get", "daemonset", "kindnet", "-o", "json").stdout)
    images = [item["image"] for item in net["spec"]["template"]["spec"]["containers"]]
    lab.check(
        "positive", "Pinned kind version and ready bundled kindnet are identified",
        any("kindnetd" in image for image in images),
        {"kind_version": kind_version, "kubernetes_version": server.get("gitVersion"),
         "cni_daemonset": "kube-system/kindnet", "cni_images": images},
    )


def run(lab):
    check_platform(lab)
    lab.kubectl("create", "namespace", NAMESPACE)
    approved_ip = add_pod(lab, APPROVED, marker=MARKERS[APPROVED])
    unapproved_ip = add_pod(lab, UNAPPROVED, marker=MARKERS[UNAPPROVED])
    add_pod(lab, CLIENT)

    # The same direct HTTP requests must succeed before any NetworkPolicy exists.
    expect_path(lab, "red", approved_ip, MARKERS[APPROVED], True,
                "Without policy, client reaches the approved owned listener and receives its marker")
    expect_path(lab, "red", unapproved_ip, MARKERS[UNAPPROVED], True,
                "Without policy, client reaches the unapproved owned listener and receives its marker")

    # Egress remains unrestricted here, so denial of the second listener is ingress evidence.
    create(lab, network_policy("stage-ingress-deny", {}, ["Ingress"]))
    create(lab, network_policy(
        "stage-ingress-approved", selector(APPROVED), ["Ingress"],
        ingress=[{"from": [{"podSelector": selector(CLIENT)}],
                  "ports": [{"protocol": "TCP", "port": PORT}]}],
    ))
    expect_path(lab, "green", unapproved_ip, MARKERS[UNAPPROVED], False,
                "Ingress isolation blocks the unapproved listener while client egress is unrestricted")
    expect_path(lab, "positive", approved_ip, MARKERS[APPROVED], True,
                "Ingress allow admits only the approved listener from the case client")

    # Permit this client's ingress to both listeners so this phase isolates egress alone.
    delete_policy(lab, "stage-ingress-deny")
    delete_policy(lab, "stage-ingress-approved")
    create(lab, network_policy(
        "stage-ingress-probe-paths", {}, ["Ingress"],
        ingress=[{"from": [{"podSelector": selector(CLIENT)}],
                  "ports": [{"protocol": "TCP", "port": PORT}]}],
    ))
    expect_path(lab, "red", unapproved_ip, MARKERS[UNAPPROVED], True,
                "Explicit ingress permits the same unapproved test path before egress enforcement")
    create(lab, network_policy("stage-egress-deny", {}, ["Egress"]))
    create(lab, network_policy(
        "stage-egress-approved", selector(CLIENT), ["Egress"],
        egress=[{"to": [{"podSelector": selector(APPROVED)}],
                 "ports": [{"protocol": "TCP", "port": PORT}]}],
    ))
    expect_path(lab, "green", unapproved_ip, MARKERS[UNAPPROVED], False,
                "Egress isolation blocks the unapproved listener while ingress allows both test paths")
    expect_path(lab, "positive", approved_ip, MARKERS[APPROVED], True,
                "Egress allow admits the case client to the approved listener")

    for name in ("stage-ingress-probe-paths", "stage-egress-deny", "stage-egress-approved"):
        delete_policy(lab, name)
    lab.kubectl("-n", NAMESPACE, "apply", "-f", str(Path(__file__).with_name("network-policy.yaml")))
    expect_path(lab, "green", unapproved_ip, MARKERS[UNAPPROVED], False,
                "Final namespace-wide ingress and egress default deny blocks the unapproved listener")
    expect_path(lab, "positive", approved_ip, MARKERS[APPROVED], True,
                "Final scoped ingress and egress rules preserve the approved HTTP observation")
    healthy = all(request(lab, "127.0.0.1", marker, client=name) for name, marker in MARKERS.items())
    lab.check("positive", "Both owned listeners remain healthy during the final denial",
              healthy, {"both_local_health_checks_passed": healthy})
