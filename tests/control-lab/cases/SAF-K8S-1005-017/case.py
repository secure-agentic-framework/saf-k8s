"""Probe recovery-scoped NetworkPolicy isolation with benign HTTP fixtures."""
import ipaddress
import json
from pathlib import Path
import runpy
import time

RECOVERY_NS = "saf-1005-017-recovery"
PROTECTED_NS = "saf-1005-017-protected"
UNRELATED_NS = "saf-1005-017-unrelated"
ROLE = "saf-k8s.example/1005-017-role"
APP = "saf-k8s.example/1005-017-app"
APPROVED_CLIENT = "approved-recovery-client"
ORDINARY_CLIENT = "ordinary-client"
ENDPOINT = "recovery-mock-endpoint"
ORDINARY_ENDPOINT = "ordinary-mock-endpoint"
PORT = 8080
APPROVED_SERVICE = "recovery-mock"
ORDINARY_SERVICE = "ordinary-mock"
MARKERS = {
    APPROVED_SERVICE: "saf-1005-017-benign-recovery-marker-61c2",
    ORDINARY_SERVICE: "saf-1005-017-benign-ordinary-marker-84a7",
}
BUSYBOX_IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
SCOPE = (
    "One disposable two-node Kind v0.32.0 cluster on Kubernetes v1.36.1 with bundled kindnet. "
    "Benign mock HTTP paths exercise independent ingress and egress enforcement, exact recovery "
    "allowances and a same-label client in another namespace. Separate checks verify least-privilege "
    "RBAC for one named receipt and revoke an old synthetic Secret-bound service account token "
    "while its replacement remains valid. Production networking, control-plane and node paths, "
    "hardware, arbitrary credentials and actual incident procedures need separate evidence."
)



def create(lab, namespace, resource):
    lab.kubectl("-n", namespace, "create", "-f", "-", payload=json.dumps(resource))


def add_namespace(lab, namespace):
    lab.kubectl("create", "namespace", namespace)


def add_pod(lab, namespace, name, role, node, *, marker=None):
    if marker is None:
        command = ["sleep", "900"]
    else:
        command = [
            "sh", "-ec",
            f"printf %s {marker} >/tmp/index.html; exec httpd -f -p {PORT} -h /tmp",
        ]
    workload = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace,
                     "labels": {ROLE: role, APP: name}},
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "nodeSelector": {"kubernetes.io/hostname": node},
            "tolerations": [{
                "key": "node-role.kubernetes.io/control-plane",
                "operator": "Exists",
                "effect": "NoSchedule",
            }],
            "containers": [{
                "name": "fixture",
                "image": BUSYBOX_IMAGE,
                "command": command,
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]},
                    "runAsNonRoot": True,
                    "runAsUser": 65534,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
            }],
        },
    }
    create(lab, namespace, workload)
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=90s", timeout=100)
    current = json.loads(lab.kubectl(
        "-n", namespace, "get", f"pod/{name}", "-o", "json").stdout)
    pod_ip = current.get("status", {}).get("podIP")
    if not pod_ip or ipaddress.ip_address(pod_ip).version != 4:
        lab.block(f"Case-owned fixture {namespace}/{name} has no IPv4 Pod IP")
    if current.get("spec", {}).get("nodeName") != node:
        lab.block(f"Case-owned fixture {namespace}/{name} is not on its assigned test node")
    if marker is not None:
        wait_local_listener(lab, namespace, name, marker)
    return pod_ip


def add_service(lab, namespace, name, role):
    create(lab, namespace, {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": name, "namespace": namespace,
                     "labels": {APP: name}},
        "spec": {
            "type": "ClusterIP",
            "selector": {ROLE: role},
            "ports": [{"name": "http", "protocol": "TCP", "port": PORT,
                       "targetPort": PORT}],
        },
    })
    current = json.loads(lab.kubectl(
        "-n", namespace, "get", "service", name, "-o", "json").stdout)
    address = current.get("spec", {}).get("clusterIP")
    if not address or address == "None":
        lab.block(f"Case-owned Service {namespace}/{name} has no ClusterIP")
    slices = json.loads(lab.kubectl(
        "-n", namespace, "get", "endpointslices", "-l", f"kubernetes.io/service-name={name}",
        "-o", "json").stdout)
    addresses = [address for item in slices["items"] for endpoint in item["endpoints"]
                 if endpoint.get("conditions", {}).get("ready")
                 for address in endpoint["addresses"]]
    if not addresses:
        lab.block(f"Case-owned Service {namespace}/{name} has no ready endpoint")
    return address, addresses


def request(lab, namespace, client, service_ip, expected_marker):
    result = lab.kubectl(
        "-n", namespace, "exec", f"pod/{client}", "--", "wget", "-q", "-T", "2",
        "-O", "-", f"http://{service_ip}:{PORT}/", allow_failure=True, timeout=12,
    )
    if result.returncode == 0:
        if result.stdout.strip() != expected_marker:
            lab.block("HTTP probe returned a response other than the fixed fixture marker")
        return True
    output = (result.stdout + result.stderr).lower()
    if any(reason in output for reason in (
            "timed out", "connection refused", "can't connect", "no route to host",
            "network is unreachable", "operation timed out", "connection reset")):
        return False
    lab.block("HTTP probe did not produce a recognized network result")


def expect_path(lab, phase, claim, namespace, client, service_ip, marker, allowed):
    deadline = time.monotonic() + 30
    consecutive = 0
    observed = None
    while time.monotonic() < deadline:
        observed = request(lab, namespace, client, service_ip, marker)
        consecutive = consecutive + 1 if observed == allowed else 0
        if consecutive == 2:
            break
        time.sleep(0.5)
    lab.check(
        phase, claim, consecutive == 2,
        {"expected_reachable": allowed, "observed_reachable": observed,
         "two_consecutive_observations": consecutive == 2,
         "source_namespace": namespace, "source_pod": client,
         "expected_fixture_marker": marker,
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
                lab.block(f"Local fixture listener {namespace}/{name} returned an unexpected marker")
            return
        time.sleep(0.5)
    lab.block(f"Case-owned fixture listener {namespace}/{name} did not become healthy")


def verify_platform_and_cni(lab):
    kind_version = lab.command("kind", "version").stdout.strip()
    if not kind_version.startswith("kind v0.32.0"):
        lab.block(f"Expected pinned kind v0.32.0, got {kind_version!r}")
    server = json.loads(lab.kubectl("version", "-o", "json").stdout).get("serverVersion", {})
    if server.get("gitVersion") != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, got {server.get('gitVersion')!r}")
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet",
                "--timeout=60s", timeout=70)
    kindnet = json.loads(lab.kubectl(
        "-n", "kube-system", "get", "daemonset", "kindnet", "-o", "json").stdout)
    images = [item.get("image", "") for item in
              kindnet.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])]
    ready = kindnet.get("status", {}).get("numberReady", 0)
    desired = kindnet.get("status", {}).get("desiredNumberScheduled", 0)
    identified = any("kindnetd" in image for image in images) and desired >= 2 and ready >= 2
    lab.check(
        "positive", "Pinned Kubernetes and bundled kindnet are ready on both nodes",
        identified,
        {"kind_version": kind_version, "kubernetes_version": server.get("gitVersion"),
         "cni_daemonset": "kube-system/kindnet", "cni_images": images,
         "ready_nodes_with_cni": ready, "desired_nodes": desired},
    )


def run(lab):
    verify_platform_and_cni(lab)
    control_node = f"{lab.cluster}-control-plane"
    worker_node = f"{lab.cluster}-worker"
    for namespace in (RECOVERY_NS, PROTECTED_NS, UNRELATED_NS):
        add_namespace(lab, namespace)

    approved_ip = add_pod(lab, RECOVERY_NS, "approved-recovery", APPROVED_CLIENT, control_node)
    ordinary_ip = add_pod(lab, RECOVERY_NS, "ordinary-client", ORDINARY_CLIENT, control_node)
    lookalike_ip = add_pod(lab, UNRELATED_NS, "lookalike-client", APPROVED_CLIENT, control_node)
    recovery_endpoint_ip = add_pod(
        lab, PROTECTED_NS, "recovery-mock-endpoint", ENDPOINT, worker_node,
        marker=MARKERS[APPROVED_SERVICE],
    )
    ordinary_endpoint_ip = add_pod(
        lab, PROTECTED_NS, "ordinary-mock-endpoint", ORDINARY_ENDPOINT, worker_node,
        marker=MARKERS[ORDINARY_SERVICE],
    )
    recovery_service_ip, recovery_service_endpoints = add_service(
        lab, PROTECTED_NS, APPROVED_SERVICE, ENDPOINT)
    ordinary_service_ip, ordinary_service_endpoints = add_service(
        lab, PROTECTED_NS, ORDINARY_SERVICE, ORDINARY_ENDPOINT)
    if recovery_service_endpoints != [recovery_endpoint_ip] or ordinary_service_endpoints != [ordinary_endpoint_ip]:
        lab.block("The owned Services do not point only to their expected case-owned endpoints")
    lab.check(
        "positive", "Source and Service endpoints are placed on separate Kind nodes",
        control_node != worker_node,
        {"source_node_role": "control-plane", "destination_node_role": "worker",
         "source_fixture_pods": ["approved-recovery", "ordinary-client", "lookalike-client"],
         "destination_fixture_pods": ["recovery-mock-endpoint", "ordinary-mock-endpoint"],
         "service_endpoints_match_exact_case_pods": True},
    )

    # Red: all sample requests have a healthy, exact case-owned path before policy.
    for namespace, client in (
            (RECOVERY_NS, "approved-recovery"), (RECOVERY_NS, "ordinary-client"),
            (UNRELATED_NS, "lookalike-client")):
        expect_path(lab, "red", "Before policy, client reaches the recovery mock Service",
                    namespace, client, recovery_service_ip, MARKERS[APPROVED_SERVICE], True)
        expect_path(lab, "red", "Before policy, client reaches the ordinary mock Service",
                    namespace, client, ordinary_service_ip, MARKERS[ORDINARY_SERVICE], True)

    case_dir = Path(__file__).resolve().parent
    lab.kubectl("-n", RECOVERY_NS, "apply", "-f", str(case_dir / "egress-default-deny.yaml"))
    expect_path(lab, "green", "Recovery namespace egress isolation fences the approved client",
                RECOVERY_NS, "approved-recovery", recovery_service_ip,
                MARKERS[APPROVED_SERVICE], False)
    expect_path(lab, "positive", "Egress policy scope leaves the unrelated namespace unaffected",
                UNRELATED_NS, "lookalike-client", recovery_service_ip,
                MARKERS[APPROVED_SERVICE], True)

    lab.kubectl("-n", RECOVERY_NS, "apply", "-f", str(case_dir / "egress-recovery-allow.yaml"))
    expect_path(lab, "positive", "Exact egress allowance restores the approved recovery Service path",
                RECOVERY_NS, "approved-recovery", recovery_service_ip,
                MARKERS[APPROVED_SERVICE], True)
    expect_path(lab, "green", "Exact egress allowance does not reach the ordinary Service",
                RECOVERY_NS, "approved-recovery", ordinary_service_ip,
                MARKERS[ORDINARY_SERVICE], False)
    expect_path(lab, "green", "Ordinary same-namespace request stays fenced",
                RECOVERY_NS, "ordinary-client", recovery_service_ip,
                MARKERS[APPROVED_SERVICE], False)

    lab.kubectl("-n", PROTECTED_NS, "apply", "-f", str(case_dir / "ingress-default-deny.yaml"))
    expect_path(lab, "green", "Protected namespace ingress isolation independently fences the allowed egress path",
                RECOVERY_NS, "approved-recovery", recovery_service_ip,
                MARKERS[APPROVED_SERVICE], False)
    expect_path(lab, "green", "Protected ingress isolation fences the same-label unrelated client",
                UNRELATED_NS, "lookalike-client", recovery_service_ip,
                MARKERS[APPROVED_SERVICE], False)

    lab.kubectl("-n", PROTECTED_NS, "apply", "-f", str(case_dir / "ingress-recovery-allow.yaml"))
    expect_path(lab, "positive", "Paired exact ingress and egress rules admit approved recovery HTTP",
                RECOVERY_NS, "approved-recovery", recovery_service_ip,
                MARKERS[APPROVED_SERVICE], True)
    expect_path(lab, "green", "Paired rules continue to fence an ordinary same-namespace request",
                RECOVERY_NS, "ordinary-client", recovery_service_ip,
                MARKERS[APPROVED_SERVICE], False)
    expect_path(lab, "green", "Paired rules fence a same-label client from an unrelated namespace",
                UNRELATED_NS, "lookalike-client", recovery_service_ip,
                MARKERS[APPROVED_SERVICE], False)
    expect_path(lab, "green", "Paired rules fence the approved client from the ordinary Service",
                RECOVERY_NS, "approved-recovery", ordinary_service_ip,
                MARKERS[ORDINARY_SERVICE], False)

    wait_local_listener(lab, PROTECTED_NS, "recovery-mock-endpoint", MARKERS[APPROVED_SERVICE])
    wait_local_listener(lab, PROTECTED_NS, "ordinary-mock-endpoint", MARKERS[ORDINARY_SERVICE])
    lab.check(
        "positive", "Both benign mock HTTP listeners stay healthy during policy denial",
        True,
        {"services": [f"{PROTECTED_NS}/{APPROVED_SERVICE}",
                      f"{PROTECTED_NS}/{ORDINARY_SERVICE}"],
         "listeners_healthy": True, "markers": list(MARKERS.values())},
    )

    runpy.run_path(str(case_dir / "recovery_identity.py"))["run"](lab)
    (lab.evidence / "isolation-observations.json").write_text(json.dumps({
        "source_node": control_node, "destination_node": worker_node,
        "sources": [approved_ip, ordinary_ip, lookalike_ip],
        "services": {
            APPROVED_SERVICE: {"cluster_ip": recovery_service_ip, "endpoints": recovery_service_endpoints},
            ORDINARY_SERVICE: {"cluster_ip": ordinary_service_ip, "endpoints": ordinary_service_endpoints},
        },
        "checks": lab.checks,
    }, indent=2, sort_keys=True) + "\n")
