"""Additive Kyverno namespace-policy provisioning checks for SAF-K8S-0501-001.

Call run_provisioning_checks(lab) after the existing 11-check case body. This
module does not create a cluster and only touches its three exact namespaces,
one GeneratingPolicy, and the pinned Kyverno release in the disposable fixture.
"""
import importlib.util
import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
KYVERNO_CASE = HERE.parent / "SAF-K8S-0605-002" / "case.py"
POLICY = "saf-0501-001-default-deny"
LABEL_KEY = "saf-k8s.example/0501-001-network-policy"
LABEL_VALUE = "enabled"
NAMESPACES = (
    "saf-0501-001-managed-a",
    "saf-0501-001-managed-b",
    "saf-0501-001-managed-late",
)
OUTSIDE = "saf-0501-001-unmanaged"
GENERATED_LABEL = "saf-k8s.example/0501-001-generated-by"
TIMEOUT = 45


def _import_pinned_installer():
    spec = importlib.util.spec_from_file_location("saf_0605_002_case", KYVERNO_CASE)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the reviewed pinned Kyverno installer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _kubectl(lab, *args, payload=None, allow_failure=False, timeout=30):
    command = [
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
        f"kind-{lab.cluster}", f"--request-timeout={max(5, timeout - 5)}s", *args,
    ]
    return lab.command(*command, payload=payload, timeout=timeout,
                       allow_failure=allow_failure)


def _namespace(name, enrolled):
    labels = {LABEL_KEY: LABEL_VALUE} if enrolled else {}
    return {"apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": name, "labels": labels}}


def _policy_objects(lab, namespace):
    result = _kubectl(lab, "-n", namespace, "get", "networkpolicies.networking.k8s.io",
                      "-l", f"{GENERATED_LABEL}={POLICY}", "-o", "json",
                      allow_failure=True)
    if result.returncode:
        return None
    return json.loads(result.stdout).get("items", [])


def _canonical_policy(namespace, direction):
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": f"saf-0501-001-default-deny-{direction}",
            "namespace": namespace,
            "labels": {
                GENERATED_LABEL: POLICY,
                "saf-k8s.example/0501-001-direction": direction,
            },
        },
        "spec": {"podSelector": {}, "policyTypes": [direction.capitalize()]},
    }


def _canonical_pair(namespace):
    # Compare only stable API fields; server metadata/status are intentionally excluded.
    return sorted((_canonical_policy(namespace, "ingress"),
                   _canonical_policy(namespace, "egress")),
                  key=lambda item: item["metadata"]["name"])


def _stable_policy(obj):
    labels = obj.get("metadata", {}).get("labels", {})
    return {
        "apiVersion": obj.get("apiVersion"),
        "kind": obj.get("kind"),
        "metadata": {
            "name": obj.get("metadata", {}).get("name"),
            "namespace": obj.get("metadata", {}).get("namespace"),
            "labels": {key: labels.get(key) for key in (
                GENERATED_LABEL, "saf-k8s.example/0501-001-direction")},
        },
        "spec": obj.get("spec", {}),
    }


def _wait_pair(lab, namespace, expected=True):
    deadline = time.monotonic() + TIMEOUT
    last = None
    while time.monotonic() < deadline:
        objects = _policy_objects(lab, namespace)
        if objects is not None:
            actual = sorted((_stable_policy(item) for item in objects),
                            key=lambda item: item["metadata"]["name"])
            last = actual
            if (actual == _canonical_pair(namespace)) == expected:
                return actual
        time.sleep(0.5)
    return last


def _check_pair(lab, namespace, description):
    actual = _wait_pair(lab, namespace, expected=True)
    okay = actual == _canonical_pair(namespace)
    lab.check("green", description, okay,
              {"namespace": namespace, "exact_ingress_egress_default_deny_pair": okay,
               "policy_count": len(actual) if actual is not None else None})
    return okay


def run_provisioning_checks(lab):
    """Install the pinned generator and exercise namespace enrollment/reconcile."""
    kyverno = _import_pinned_installer()
    # The existing SAF-K8S-0605-002 helper pins Kyverno v1.20.0 and chart
    # 3.10.0 by SHA-256. Empty values avoid enabling unrelated registry tests.
    values = lab.kubeconfig.parent / "saf-0501-001-kyverno-values.json"
    values.write_text("{}\n", encoding="utf-8")
    kyverno._install_kyverno(lab, values)
    for deployment in (
        "kyverno-admission-controller",
        "kyverno-background-controller",
        "kyverno-cleanup-controller",
        "kyverno-reports-controller",
    ):
        _kubectl(lab, "-n", "kyverno", "rollout", "status",
                 f"deployment/{deployment}", "--timeout=90s", timeout=100)
    pods = json.loads(_kubectl(lab, "-n", "kyverno", "get", "pods", "-o", "json").stdout)["items"]
    images = sorted({container["image"] for pod in pods
                     for container in pod["spec"].get("containers", [])})
    expected = {f"reg.kyverno.io/kyverno/{name}:v1.20.0" for name in (
        "kyverno", "background-controller", "cleanup-controller", "reports-controller")}
    pinned = expected.issubset(images)
    lab.check("positive", "Pinned Kyverno v1.20.0 generator controllers are ready",
              pinned, {"chart": "3.10.0", "controller_images_pinned": pinned})

    role = "saf-0501-001-networkpolicy-generation"
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": role},
                "rules": [{"apiGroups": ["networking.k8s.io"], "resources": ["networkpolicies"],
                           "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": role},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": role},
                "subjects": [{"kind": "ServiceAccount", "name": "kyverno-background-controller", "namespace": "kyverno"}]})

    policy_path = HERE / "generating-policy.yaml"
    _kubectl(lab, "apply", "-f", "-", payload=policy_path.read_text(encoding="utf-8"))
    kyverno._wait_policy_ready(lab, "GeneratingPolicy", POLICY)
    lab.check("positive", "GeneratingPolicy is Ready before namespace enrollment",
              True, {"policy": POLICY, "ready": True})

    _kubectl(lab, "create", "-f", "-", payload=json.dumps(_namespace(NAMESPACES[0], True)))
    _kubectl(lab, "create", "-f", "-", payload=json.dumps(_namespace(NAMESPACES[1], True)))
    _kubectl(lab, "create", "-f", "-", payload=json.dumps(_namespace(OUTSIDE, True)))
    pair_a = _wait_pair(lab, NAMESPACES[0])
    pair_b = _wait_pair(lab, NAMESPACES[1])
    lab.check("green", "Two enrolled namespaces each receive exact ingress and egress default deny",
              pair_a == _canonical_pair(NAMESPACES[0]) and pair_b == _canonical_pair(NAMESPACES[1]),
              {"managed_namespace_count": 2,
               "both_exact_policy_pairs": pair_a == _canonical_pair(NAMESPACES[0])
               and pair_b == _canonical_pair(NAMESPACES[1])})

    _kubectl(lab, "create", "-f", "-", payload=json.dumps(_namespace(NAMESPACES[2], False)))
    time.sleep(2)
    late_before = _policy_objects(lab, NAMESPACES[2])
    outside_before = _policy_objects(lab, OUTSIDE)
    excluded = late_before == [] and outside_before == []
    lab.check("red", "Unenrolled and out-of-scope namespaces receive no generated policy",
              excluded, {"late_unenrolled_empty": late_before == [],
                         "outside_scope_empty": outside_before == []})

    _kubectl(lab, "label", "namespace", NAMESPACES[2], f"{LABEL_KEY}={LABEL_VALUE}",
             timeout=20)
    pair_late = _wait_pair(lab, NAMESPACES[2])
    lab.check("green", "A newly enrolled namespace receives the exact policy pair on label update",
              pair_late == _canonical_pair(NAMESPACES[2]),
              {"namespace": NAMESPACES[2],
               "newly_enrolled_exact_pair": pair_late == _canonical_pair(NAMESPACES[2])})

    # Test synchronization on a single owned generated object. Kyverno should
    # recreate a deleted downstream object while the trigger and policy remain.
    policy_name = "saf-0501-001-default-deny-ingress"
    previous_uid = _kubectl(lab, "-n", NAMESPACES[0], "get", "networkpolicy", policy_name,
                            "-o", "jsonpath={.metadata.uid}").stdout.strip()
    _kubectl(lab, "-n", NAMESPACES[0], "delete", "networkpolicy", policy_name, "--wait=true", timeout=20)
    restored = _wait_pair(lab, NAMESPACES[0])
    after_uid = _kubectl(lab, "-n", NAMESPACES[0], "get", "networkpolicy", policy_name,
                         "-o", "jsonpath={.metadata.uid}", allow_failure=True)
    new_identity = after_uid.returncode == 0 and bool(previous_uid) and after_uid.stdout.strip() != previous_uid
    lab.check("positive", "Deleting one generated policy is reconciled to the canonical pair",
              restored == _canonical_pair(NAMESPACES[0]) and new_identity,
              {"deleted_ingress_policy_recreated": restored == _canonical_pair(NAMESPACES[0]) and new_identity,
               "egress_policy_present": bool(restored and any(
                   item["metadata"]["name"].endswith("-egress") for item in restored))})
