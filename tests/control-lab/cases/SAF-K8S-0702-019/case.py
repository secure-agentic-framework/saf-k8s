"""Demonstrate layered namespace controls with synthetic AI and general fixtures."""
import json
from pathlib import Path
import time

from fixtures import container, pod


AI = "saf-0702-019-ai"
GENERAL = "saf-0702-019-general"
APP = "saf-k8s.example/0702-019"
PORT = 8080
RECORD = "synthetic-record"
MARKERS = {AI: "ai-namespace-fixed-marker", GENERAL: "general-namespace-fixed-marker"}
DENIAL = "AI workloads in this namespace require an approved workload classification"
CLASSIFICATION = {"saf-k8s.example/workload-type": "inference"}
SCOPE = (
    "One disposable kind cluster with two case-owned namespaces, one labeled synthetic AI and "
    "one general. Tests named ConfigMap GET under a namespace Role/RoleBinding, fixed IPv4 "
    "TCP/8080 Pod paths across AI-namespace ingress and egress default deny, and Pod "
    "CREATE admission selected only for the AI namespace. No external destinations, real data, "
    "privileged workloads, other CNIs/platforms, production rollout, periodic validation, "
    "human review, tenant policy administration, or cross-platform deployment is established."
)


def create(lab, resource):
    namespace = resource["metadata"].get("namespace")
    if namespace:
        lab.kubectl("-n", namespace, "create", "-f", "-", payload=json.dumps(resource))
    else:
        lab.kubectl("create", "-f", "-", payload=json.dumps(resource))


def identity(namespace):
    return f"system:serviceaccount:{namespace}:case-reader"


def access(lab, acting_namespace, target_namespace, name, allowed, marker=None):
    result = lab.kubectl(
        "--as", identity(acting_namespace),
        "--as-group=system:serviceaccounts",
        f"--as-group=system:serviceaccounts:{acting_namespace}",
        "--as-group=system:authenticated", "-n", target_namespace,
        "get", "configmap", name, "-o", "json", allow_failure=True,
    )
    if allowed:
        observed = None
        if result.returncode == 0:
            try:
                observed = json.loads(result.stdout)["data"]["marker"]
            except (KeyError, json.JSONDecodeError):
                lab.block("Permitted API read returned malformed synthetic data")
        lab.check("positive", f"{acting_namespace} reads {target_namespace}/{name}",
                  result.returncode == 0 and observed == marker,
                  {"returncode": result.returncode, "marker": observed})
    else:
        forbidden = result.returncode != 0 and "forbidden" in result.stderr.lower()
        lab.check("green", f"{acting_namespace} is denied {target_namespace}/{name}", forbidden,
                  {"returncode": result.returncode, "forbidden": forbidden,
                   "detail": result.stderr.strip()})


def add_reader(lab, namespace):
    create(lab, {"apiVersion": "v1", "kind": "ServiceAccount",
                 "metadata": {"name": "case-reader", "namespace": namespace},
                 "automountServiceAccountToken": False})
    create(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                 "metadata": {"name": "read-one-record", "namespace": namespace},
                 "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                            "resourceNames": [RECORD], "verbs": ["get"]}]})
    create(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                 "metadata": {"name": "case-reader", "namespace": namespace},
                 "subjects": [{"kind": "ServiceAccount", "name": "case-reader",
                               "namespace": namespace, "apiGroup": ""}],
                 "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                             "name": "read-one-record"}})


def listener(lab, namespace):
    workload = pod("fixed-listener", [container("listener", command=[
        "sh", "-ec", f"printf %s {MARKERS[namespace]} >/tmp/index.html; "
        f"exec httpd -f -p {PORT} -h /tmp",
    ])], automountServiceAccountToken=False)
    workload["metadata"].update(namespace=namespace, labels={APP: "listener"})
    create(lab, workload)
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", "pod/fixed-listener",
                "--timeout=90s", timeout=100)
    current = json.loads(lab.kubectl("-n", namespace, "get", "pod/fixed-listener",
                                     "-o", "json").stdout)
    if not current.get("status", {}).get("podIP"):
        lab.block("Fixed listener has no Pod IP")
    return current["status"]["podIP"]


def client(lab, namespace):
    workload = pod("fixed-client", [container("client")], automountServiceAccountToken=False)
    workload["metadata"].update(namespace=namespace, labels={APP: "client"})
    create(lab, workload)
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", "pod/fixed-client",
                "--timeout=90s", timeout=100)


def request(lab, source_namespace, destination_ip, marker):
    result = lab.kubectl("-n", source_namespace, "exec", "pod/fixed-client", "--",
                         "wget", "-q", "-T", "2", "-O", "-",
                         f"http://{destination_ip}:{PORT}/", allow_failure=True, timeout=12)
    if result.returncode == 0:
        if result.stdout.strip() != marker:
            lab.block("Fixed HTTP probe returned an unexpected marker")
        return True
    if any(reason in (result.stdout + result.stderr).lower() for reason in (
            "timed out", "connection refused", "no route to host", "network is unreachable")):
        return False
    lab.block("Fixed HTTP probe did not return a network outcome")


def expect_path(lab, phase, source_namespace, destination_ip, marker, allowed):
    deadline = time.monotonic() + 20
    consecutive = 0
    observed = None
    while time.monotonic() < deadline:
        observed = request(lab, source_namespace, destination_ip, marker)
        consecutive = consecutive + 1 if observed == allowed else 0
        if consecutive == 2:
            break
        time.sleep(0.5)
    lab.check(phase, f"{source_namespace} {'reaches' if allowed else 'cannot reach'} fixed listener",
              consecutive == 2,
              {"expected_reachable": allowed, "observed_reachable": observed,
               "two_consecutive_observations": consecutive == 2,
               "destination_port": PORT})


def pod_request(namespace, name, classification=None):
    workload = pod(name, [container("fixed-probe")], automountServiceAccountToken=False)
    workload["metadata"].update(namespace=namespace,
                                labels=dict(classification or {}))
    return workload


def admission(lab, namespace, resource):
    return lab.kubectl("-n", namespace, "create", "-f", "-", "--dry-run=server", "-o", "json",
                       payload=json.dumps(resource), allow_failure=True)


def exact_denial(result):
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and DENIAL in result.stderr)


def run(lab):
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet",
                "--timeout=60s", timeout=70)
    lab.kubectl("create", "namespace", AI)
    lab.kubectl("label", "namespace", AI, "saf-k8s.example/tenant-class=ai")
    lab.kubectl("create", "namespace", GENERAL)
    for namespace in (AI, GENERAL):
        create(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                     "metadata": {"name": RECORD, "namespace": namespace},
                     "data": {"marker": f"{namespace}-synthetic"}})
        create(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                     "metadata": {"name": "other-record", "namespace": namespace},
                     "data": {"marker": "out-of-scope-synthetic"}})

    access(lab, AI, AI, RECORD, False)
    add_reader(lab, AI)
    access(lab, AI, AI, RECORD, True, f"{AI}-synthetic")
    access(lab, AI, AI, "other-record", False)
    access(lab, AI, GENERAL, RECORD, False)

    addresses = {namespace: listener(lab, namespace) for namespace in (AI, GENERAL)}
    for namespace in (AI, GENERAL):
        client(lab, namespace)
    expect_path(lab, "red", AI, addresses[AI], MARKERS[AI], True)
    expect_path(lab, "red", GENERAL, addresses[AI], MARKERS[AI], True)
    expect_path(lab, "red", AI, addresses[GENERAL], MARKERS[GENERAL], True)

    valid_ai = pod_request(AI, "admission-valid", CLASSIFICATION)
    missing_ai = pod_request(AI, "admission-missing")
    wrong_ai = pod_request(AI, "admission-wrong", {"saf-k8s.example/workload-type": "unknown"})
    missing_general = pod_request(GENERAL, "admission-general-unclassified")
    red = [admission(lab, AI, missing_ai), admission(lab, AI, wrong_ai)]
    lab.check("red", "Before policy, both invalid AI Pod CREATE dry-runs are admitted",
              all(result.returncode == 0 for result in red),
              [{"accepted": result.returncode == 0, "detail": result.stderr.strip()}
               for result in red])

    lab.apply(Path(__file__).with_name("admission-policy.yaml"))
    deadline = time.monotonic() + 15
    while True:
        green = [admission(lab, AI, missing_ai), admission(lab, AI, wrong_ai)]
        positives = [admission(lab, AI, valid_ai), admission(lab, GENERAL, missing_general)]
        if (all(exact_denial(result) for result in green)
                and all(result.returncode == 0 for result in positives)
                or time.monotonic() >= deadline):
            break
        time.sleep(0.5)
    lab.check("green", "AI namespace rejects missing and unapproved classification exactly",
              all(exact_denial(result) for result in green),
              [{"denied_by_policy": exact_denial(result), "detail": result.stderr.strip()}
               for result in green])
    lab.check("positive", "Valid AI and unselected general-namespace Pods remain admissible",
              all(result.returncode == 0 for result in positives),
              [{"accepted": result.returncode == 0, "detail": result.stderr.strip()}
               for result in positives])

    lab.kubectl("-n", AI, "apply", "-f", str(Path(__file__).with_name("network-policy.yaml")))
    expect_path(lab, "green", GENERAL, addresses[AI], MARKERS[AI], False)
    expect_path(lab, "green", AI, addresses[GENERAL], MARKERS[GENERAL], False)
    expect_path(lab, "positive", AI, addresses[AI], MARKERS[AI], True)
    expect_path(lab, "positive", GENERAL, addresses[GENERAL], MARKERS[GENERAL], True)
