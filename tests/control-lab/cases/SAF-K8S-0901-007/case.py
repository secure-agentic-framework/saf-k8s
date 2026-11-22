"""Verify named, namespaced RBAC for an inert synthetic AI controller identity."""
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
CONTROL_ID = "SAF-K8S-0901-007"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13.16-slim@sha256:"
    "70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f"
)
OPERATOR_NS = "saf-0901-007-operator"
WORKLOAD_NS = "saf-0901-007-workloads"
ADJACENT_NS = "saf-0901-007-adjacent"
CONTROLLER_SA = "saf-0901-007-controller"
PROBE_CONFIG = "saf-0901-007-probe"
NAMED_RESOURCE = "mock-raycluster-spec"
SIBLING_RESOURCE = "mock-raycluster-neighbor"
EXPECTED_SUBJECT = f"system:serviceaccount:{OPERATOR_NS}:{CONTROLLER_SA}"
PROBE_OPERATIONS = {
    "get_named": ("GET", WORKLOAD_NS, f"configmaps/{NAMED_RESOURCE}"),
    "patch_named": ("PATCH", WORKLOAD_NS, f"configmaps/{NAMED_RESOURCE}"),
    "get_sibling": ("GET", WORKLOAD_NS, f"configmaps/{SIBLING_RESOURCE}"),
    "get_adjacent_namespace": ("GET", ADJACENT_NS, f"configmaps/{NAMED_RESOURCE}"),
    "list_configmaps": ("GET", WORKLOAD_NS, "configmaps"),
    "get_secret_collection": ("GET", WORKLOAD_NS, "secrets"),
}
SCOPE = (
    "Disposable Kind Kubernetes v1.36.1 cluster with a digest-pinned node image. "
    "A named controller ServiceAccount in a synthetic operator namespace uses a projected "
    "token to GET and PATCH one named mock workload ConfigMap through a RoleBinding in a "
    "separate workload namespace. Before/after direct API calls and independent kubectl auth "
    "checks show the denied adjacent namespace, sibling resource, list/Secret access, and "
    "cluster-scoped access. No actual AI operator, CRD, GPU, external target, feed, scan, or "
    "vendor upgrade is exercised; operational applicability and version-specific vendor "
    "permissions remain unresolved."
)


def _check_can_i(lab, verb, resource, namespace):
    args = ["auth", "can-i", verb, resource, f"--as={EXPECTED_SUBJECT}"]
    if namespace:
        args.extend(("-n", namespace))
    result = lab.kubectl(*args, allow_failure=True)
    answer = result.stdout.strip().lower()
    if (answer, result.returncode) not in {("yes", 0), ("no", 1)}:
        lab.block("kubectl auth can-i returned an unexpected answer")
    return answer == "yes"


def _authorization_matrix(lab):
    return {
        "get_named": _check_can_i(lab, "get", f"configmap/{NAMED_RESOURCE}", WORKLOAD_NS),
        "patch_named": _check_can_i(lab, "patch", f"configmap/{NAMED_RESOURCE}", WORKLOAD_NS),
        "get_sibling": _check_can_i(lab, "get", f"configmap/{SIBLING_RESOURCE}", WORKLOAD_NS),
        "get_adjacent_namespace": _check_can_i(
            lab, "get", f"configmap/{NAMED_RESOURCE}", ADJACENT_NS),
        "list_configmaps": _check_can_i(lab, "list", "configmaps", WORKLOAD_NS),
        "get_secrets": _check_can_i(lab, "get", "secrets", WORKLOAD_NS),
        "get_nodes": _check_can_i(lab, "get", "nodes", None),
    }


def _make_probe_pod(name):
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": OPERATOR_NS,
            "labels": {"saf-lab.example/control": CONTROL_ID,
                       "saf-lab.example/fixture": "synthetic-rbac-probe"},
        },
        "spec": {
            "serviceAccountName": CONTROLLER_SA,
            "automountServiceAccountToken": True,
            "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "probe",
                "image": PYTHON_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "/fixture/probe.py"],
                "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                              "limits": {"cpu": "100m", "memory": "96Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False,
                                     "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [{"name": "probe", "mountPath": "/fixture",
                                  "readOnly": True}],
            }],
            "volumes": [{"name": "probe", "configMap": {"name": PROBE_CONFIG}}],
        },
    }


def _run_probe(lab, phase):
    pod_name = f"saf-0901-007-probe-{phase}"
    lab.kubectl("-n", OPERATOR_NS, "create", "-f", "-",
                payload=json.dumps(_make_probe_pod(pod_name)))
    lab.kubectl("-n", OPERATOR_NS, "wait", "--for=jsonpath={.status.phase}=Succeeded",
                f"pod/{pod_name}", "--timeout=100s", timeout=110)
    raw_lines = lab.kubectl("-n", OPERATOR_NS, "logs", pod_name).stdout.splitlines()
    try:
        records = [json.loads(line) for line in raw_lines if line.strip()]
    except json.JSONDecodeError:
        lab.block("Probe output was not valid JSON evidence")
    identity = next((item.get("subject") for item in records
                     if item.get("operation") == "projected_service_account_identity"), None)
    operations = {item.get("operation"): item for item in records
                  if item.get("operation") in PROBE_OPERATIONS}
    if identity != EXPECTED_SUBJECT or set(operations) != set(PROBE_OPERATIONS):
        lab.block("Probe identity or direct API evidence was incomplete")
    return {"identity": identity, "operations": operations}


def _phase_matches(observed, expected_statuses):
    operations = observed["operations"]
    if any(operations[name].get("status") != status
           for name, status in expected_statuses.items()):
        return False
    if expected_statuses.get("get_named") == 200:
        if operations["get_named"].get("fixture_marker_matches") is not True:
            return False
    if expected_statuses.get("patch_named") == 200:
        if operations["patch_named"].get("synthetic_reconcile_marker_persisted") is not True:
            return False
    return True


def _inspect_role_binding(lab):
    role = json.loads(lab.kubectl(
        "-n", WORKLOAD_NS, "get", "role", "saf-0901-007-controller-workload", "-o", "json",
    ).stdout)
    binding = json.loads(lab.kubectl(
        "-n", WORKLOAD_NS, "get", "rolebinding", "saf-0901-007-controller-workload", "-o", "json",
    ).stdout)
    rules = role.get("rules", [])
    valid_rule = rules == [{
        "apiGroups": [""], "resources": ["configmaps"],
        "resourceNames": [NAMED_RESOURCE], "verbs": ["get", "patch"],
    }]
    subjects = binding.get("subjects", [])
    valid_binding = (
        binding.get("roleRef", {}).get("kind") == "Role"
        and binding.get("roleRef", {}).get("name") == role.get("metadata", {}).get("name")
        and len(subjects) == 1
        and subjects[0].get("kind") == "ServiceAccount"
        and subjects[0].get("name") == CONTROLLER_SA
        and subjects[0].get("namespace") == OPERATOR_NS
    )
    return {"role": role, "role_binding": binding,
            "role_is_exact_named_get_patch": valid_rule,
            "binding_is_cross_namespace_controller_only": valid_binding}


def run(lab):
    lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig),
                "--context", f"kind-{lab.cluster}", "--request-timeout=40s",
                "apply", "-f", str(HERE / "fixtures.yaml"))

    red_authz = _authorization_matrix(lab)
    red = _run_probe(lab, "red")
    red_expected = {operation: 403 for operation in PROBE_OPERATIONS}
    lab.check(
        "red",
        "An unbound synthetic controller identity is denied every mock workload API operation",
        all(answer is False for answer in red_authz.values())
        and _phase_matches(red, red_expected),
        {"kubectl_auth_can_i": red_authz, "projected_token_api_observations": red},
    )

    lab.kubectl("-n", WORKLOAD_NS, "apply", "-f", str(HERE / "role-and-binding.yaml"))
    green_authz = _authorization_matrix(lab)
    green = _run_probe(lab, "green")
    green_expected = {
        "get_named": 200, "patch_named": 200, "get_sibling": 403,
        "get_adjacent_namespace": 403, "list_configmaps": 403,
        "get_secret_collection": 403,
    }
    authz_expected = {
        "get_named": True, "patch_named": True, "get_sibling": False,
        "get_adjacent_namespace": False, "list_configmaps": False,
        "get_secrets": False, "get_nodes": False,
    }
    lab.check(
        "green",
        "Controller permissions allow only GET and PATCH on the named workload ConfigMap",
        green_authz == authz_expected and _phase_matches(green, green_expected),
        {"kubectl_auth_can_i": green_authz, "projected_token_api_observations": green},
    )

    policy = _inspect_role_binding(lab)
    named_after = json.loads(lab.kubectl(
        "-n", WORKLOAD_NS, "get", "configmap", NAMED_RESOURCE, "-o", "json",
    ).stdout)
    patch_persisted = (
        named_after.get("metadata", {}).get("annotations", {}).get(
            "saf-lab.example/controller-observed") == "true"
        and named_after.get("data", {}).get("fixture_id") == "SYNTH-0901-007-WORKLOAD-001"
    )
    lab.check(
        "positive",
        "Independent control-plane read confirms the allowed named resource changed and RBAC stayed bounded",
        patch_persisted and policy["role_is_exact_named_get_patch"]
        and policy["binding_is_cross_namespace_controller_only"],
        {"persisted_mock_resource": {
            "namespace": WORKLOAD_NS, "name": NAMED_RESOURCE,
            "fixture_id": named_after.get("data", {}).get("fixture_id"),
            "controller_observed": patch_persisted,
        }, "role_is_exact_named_get_patch": policy["role_is_exact_named_get_patch"],
            "binding_is_cross_namespace_controller_only":
                policy["binding_is_cross_namespace_controller_only"]},
    )

    evidence = {
        "control_id": CONTROL_ID,
        "cluster_kubernetes_version_target": "v1.36.1",
        "node_image": NODE_IMAGE,
        "probe_image": PYTHON_IMAGE,
        "identity": EXPECTED_SUBJECT,
        "red": {"kubectl_auth_can_i": red_authz,
                "projected_token_api_observations": red["operations"]},
        "green": {"kubectl_auth_can_i": green_authz,
                  "projected_token_api_observations": green["operations"]},
        "role": policy["role"],
        "role_binding": policy["role_binding"],
        "independent_resource_read": {
            "namespace": WORKLOAD_NS, "name": NAMED_RESOURCE,
            "fixture_id": named_after.get("data", {}).get("fixture_id"),
            "resource_version": named_after.get("metadata", {}).get("resourceVersion"),
            "controller_observed": patch_persisted,
        },
        "secrets_included": False,
        "boundary": "synthetic fixtures and metadata only; no tokens, secret data, real operator, or external target",
    }
    (lab.evidence / "operator-rbac-observations.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
