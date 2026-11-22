"""Audit additive RBAC grants for a synthetic ServiceAccount using SAR."""
import json
from pathlib import Path
import time

HERE = Path(__file__).parent
NAMESPACE = "saf-0401-002"
SERVICE_ACCOUNT = "saf-0401-002-audited-reader"
SUBJECT = f"system:serviceaccount:{NAMESPACE}:{SERVICE_ACCOUNT}"
GROUPS = [
    "system:serviceaccounts",
    f"system:serviceaccounts:{NAMESPACE}",
    "system:authenticated",
]
REQUIRED = "saf-0401-002-required-config"
UNNEEDED = "saf-0401-002-unneeded-config"
REQUIRED_ROLE = "saf-0401-002-required-reader"
UNNEEDED_ROLE = "saf-0401-002-unneeded-reader"
UNNEEDED_BINDING = "saf-0401-002-unneeded-reader"

SCOPE = (
    "Kubernetes v1.36.1 RBAC for one synthetic ServiceAccount, two case-owned "
    "Roles, two RoleBindings, and two named ConfigMaps in namespace "
    f"{NAMESPACE}. Kubernetes SubjectAccessReview requests evaluate only named "
    "get actions for that synthetic identity. The test removes only the "
    "case-owned binding for the unnecessary read. Cluster-scoped RBAC, other "
    "subjects, privilege-escalation paths, real data, admission controls, and "
    "production audit coverage are outside this case."
)


def named_get_review(name):
    return {
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SubjectAccessReview",
        "spec": {
            "user": SUBJECT,
            "groups": GROUPS,
            "resourceAttributes": {
                "namespace": NAMESPACE,
                "verb": "get",
                "group": "",
                "resource": "configmaps",
                "name": name,
            },
        },
    }


def review(lab, name):
    result = lab.kubectl(
        "create", "-f", "-", "-o", "json",
        payload=json.dumps(named_get_review(name)),
    )
    response = json.loads(result.stdout)
    status = response["status"]
    if status.get("evaluationError"):
        raise RuntimeError(f"SubjectAccessReview evaluation failed: {status['evaluationError']}")
    return {
        "allowed": status.get("allowed", False),
        "denied": status.get("denied", False),
        "reason": status.get("reason", ""),
    }


def role_rules(lab, name):
    result = lab.kubectl("-n", NAMESPACE, "get", "role", name, "-o", "json")
    return json.loads(result.stdout).get("rules", [])


def named_get_rule(configmap):
    return [{
        "apiGroups": [""],
        "resources": ["configmaps"],
        "resourceNames": [configmap],
        "verbs": ["get"],
    }]


def binding_exists(lab, name):
    result = lab.kubectl(
        "-n", NAMESPACE, "get", "rolebinding", name,
        "-o", "name", allow_failure=True,
    )
    return result.returncode == 0 and result.stdout.strip() == f"rolebinding.rbac.authorization.k8s.io/{name}"


def binding_matches(lab, binding, role):
    result = lab.kubectl("-n", NAMESPACE, "get", "rolebinding", binding, "-o", "json")
    body = json.loads(result.stdout)
    return (
        body.get("roleRef") == {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": role,
        }
        and body.get("subjects") == [{
            "kind": "ServiceAccount",
            "name": SERVICE_ACCOUNT,
            "namespace": NAMESPACE,
        }]
    )


def wait_for_remediated_decisions(lab, timeout=10):
    deadline = time.monotonic() + timeout
    while True:
        required = review(lab, REQUIRED)
        unneeded = review(lab, UNNEEDED)
        if required["allowed"] and not unneeded["allowed"]:
            return required, unneeded
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "SubjectAccessReview decisions did not reflect the binding removal "
                f"within {timeout}s: required={required}; unneeded={unneeded}"
            )
        time.sleep(0.2)


def run(lab):
    # The fresh cluster is isolated; every object in this manifest is case-owned.
    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl("-n", NAMESPACE, "apply", "-f", str(HERE / "fixtures.yaml"))

    declared_required = role_rules(lab, REQUIRED_ROLE)
    declared_unneeded = role_rules(lab, UNNEEDED_ROLE)
    required_binding_matches = binding_matches(lab, REQUIRED_ROLE, REQUIRED_ROLE)
    unneeded_binding_matches = binding_matches(lab, UNNEEDED_BINDING, UNNEEDED_ROLE)
    required_before = review(lab, REQUIRED)
    unneeded_before = review(lab, UNNEEDED)

    lab.check(
        "red",
        "The declared narrow Role and extra named-read Role combine additively; the audit detects the unnecessary read",
        declared_required == named_get_rule(REQUIRED)
        and declared_unneeded == named_get_rule(UNNEEDED)
        and binding_exists(lab, REQUIRED_ROLE)
        and binding_exists(lab, UNNEEDED_BINDING)
        and required_binding_matches
        and unneeded_binding_matches
        and required_before["allowed"]
        and unneeded_before["allowed"],
        {
            "required_role_rules": declared_required,
            "unneeded_role_rules": declared_unneeded,
            "required_binding_matches": required_binding_matches,
            "unneeded_binding_matches": unneeded_binding_matches,
            "required_named_get": required_before,
            "unneeded_named_get": unneeded_before,
            "both_bindings_present": True,
        },
    )

    # Remove only the binding that supplies the unnecessary ordinary read.
    lab.kubectl("-n", NAMESPACE, "delete", "rolebinding", UNNEEDED_BINDING)

    required_after, unneeded_after = wait_for_remediated_decisions(lab)
    required_binding_after = binding_exists(lab, REQUIRED_ROLE)
    unneeded_binding_after = binding_exists(lab, UNNEEDED_BINDING)
    lab.check(
        "green",
        "Removing the identified case-only binding denies the unnecessary named read while retaining the required read grant",
        required_after["allowed"]
        and not unneeded_after["allowed"]
        and required_binding_after
        and not unneeded_binding_after,
        {
            "required_named_get": required_after,
            "unneeded_named_get": unneeded_after,
            "required_binding_remains": required_binding_after,
            "unneeded_binding_removed": not unneeded_binding_after,
        },
    )

    # Retain an explicit positive result for the operation still required.
    permitted = review(lab, REQUIRED)
    lab.check(
        "positive",
        "The required named ConfigMap get remains authorized after remediation",
        permitted["allowed"],
        {"subject": SUBJECT, "namespace": NAMESPACE, "verb": "get",
         "resource": "configmaps", "name": REQUIRED, **permitted},
    )
