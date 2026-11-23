"""Demonstrate bounded training/production separation with Kubernetes APIs."""
import json
import time

NAMESPACE_TRAINING = "saf-test"
NAMESPACE_PRODUCTION = "saf-test-production"
TRAINING_SA = "saf-0905-012-training-runner"
PRODUCTION_SA = "saf-0905-012-inference-runner"
TRAINING_CM = "saf-0905-012-training-input"
PRODUCTION_CM = "saf-0905-012-inference-input"
ROLE = "saf-0905-012-local-fixture-reader"
POLICY = "saf-0905-012-production-configmap-boundary"
POLICY_BINDING = "saf-0905-012-production-configmap-boundary"

SCOPE = (
    "A disposable Kubernetes v1.36.1 Kind cluster uses saf-test as a training namespace "
    "and a case-owned production namespace. Two fixed ServiceAccounts access only inert, "
    "application-owned synthetic ConfigMaps. Matched SubjectAccessReview decisions show "
    "no access before scoped Roles, then namespace-scoped own-reference access while "
    "cross-environment access remains denied. A stable "
    "ValidatingAdmissionPolicy denies an inference Pod volume referencing the training "
    "ConfigMap; server dry-run compares the same request before and after policy enrollment, "
    "and admits the valid inference reference. This establishes bounded namespace/RBAC and "
    "Pod-volume admission behavior for synthetic references only. Cloud workload identity "
    "federation, real credentials or data, production clusters, other reference forms, and "
    "organization-wide production coverage require separate evidence."
)


def _namespace(name, environment):
    return {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": name,
            "labels": {"saf-k8s.example/environment": environment},
        },
    }


def _configmap(namespace, name, environment):
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {"saf-k8s.example/environment": environment},
        },
        "data": {"reference": f"app://synthetic/{environment}/input-v1"},
    }


def _service_account(namespace, name):
    return {"apiVersion": "v1", "kind": "ServiceAccount",
            "metadata": {"name": name, "namespace": namespace},
            "automountServiceAccountToken": False}


def _role(namespace, configmap):
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": ROLE, "namespace": namespace},
        "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                   "resourceNames": [configmap], "verbs": ["get"]}],
    }


def _role_binding(namespace, service_account):
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {"name": ROLE, "namespace": namespace},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": ROLE},
        "subjects": [{"kind": "ServiceAccount", "name": service_account,
                      "namespace": namespace}],
    }


def _access_review(service_account, namespace, configmap):
    """Ask the authorization API for a fixed test principal; do not impersonate it."""
    return {
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SubjectAccessReview",
        "spec": {
            "user": f"system:serviceaccount:{service_account[0]}:{service_account[1]}",
            "resourceAttributes": {"namespace": namespace, "verb": "get",
                                   "group": "", "resource": "configmaps",
                                   "name": configmap},
        },
    }


def _review(lab, service_account, namespace, configmap):
    result = lab.create(_access_review(service_account, namespace, configmap))
    status = result.get("status", {})
    return {"allowed": status.get("allowed") is True,
            "denied": status.get("denied") is True,
            "reason": status.get("reason", ""),
            "evaluationError": status.get("evaluationError", "")}


def _pod(name, namespace, service_account, configmap):
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace,
                     "labels": {"saf-k8s.example/workload": "inference-fixture"}},
        "spec": {
            "serviceAccountName": service_account,
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "containers": [{"name": "inference-fixture",
                             "image": "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec",
                             "command": ["cat", "/app/input/reference"],
                             "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                           "limits": {"cpu": "100m", "memory": "32Mi"}},
                             "volumeMounts": [{"name": "input", "mountPath": "/app/input",
                                               "readOnly": True}],
                             "securityContext": {"allowPrivilegeEscalation": False,
                                                 "readOnlyRootFilesystem": True,
                                                 "capabilities": {"drop": ["ALL"]}}}],
            "volumes": [{"name": "input", "configMap": {"name": configmap}}],
        },
    }


def _admission_policy():
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": POLICY},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {"resourceRules": [{"apiGroups": [""],
                "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"],
                "resources": ["pods"]}]},
            "validations": [{
                "expression": "!has(object.spec.volumes) || object.spec.volumes.all(volume, !has(volume.configMap) || volume.configMap.name != '" + TRAINING_CM + "')",
                "message": "production Pods cannot reference the training input ConfigMap",
                "reason": "Forbidden",
            }],
        },
    }


def _admission_binding():
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": POLICY_BINDING},
        "spec": {
            "policyName": POLICY,
            "validationActions": ["Deny"],
            "matchResources": {"namespaceSelector": {"matchLabels": {
                "saf-k8s.example/environment": "production"}}},
        },
    }


def _server_dry_run(lab, obj):
    return lab.kubectl("-n", obj["metadata"]["namespace"], "create", "-f", "-", "--dry-run=server", "-o", "json",
                       payload=json.dumps(obj), allow_failure=True)


def _is_policy_denial(result):
    message = result.stderr
    return (result.returncode != 0 and "(Forbidden)" in message
            and f"ValidatingAdmissionPolicy '{POLICY}'" in message
            and f"binding '{POLICY_BINDING}'" in message
            and "production Pods cannot reference the training input ConfigMap" in message)


def _create(lab, obj):
    namespace = obj.get("metadata", {}).get("namespace")
    if namespace is None:
        return lab.create(obj)
    result = lab.kubectl("-n", namespace, "create", "-f", "-", "-o", "json", payload=json.dumps(obj))
    return json.loads(result.stdout)


def run(lab):
    # saf-test is pre-created by the lab runner; apply its environment label.
    lab.kubectl("label", "namespace", NAMESPACE_TRAINING,
                "saf-k8s.example/environment=training", "--overwrite")
    lab.create(_namespace(NAMESPACE_PRODUCTION, "production"))
    _create(lab, _configmap(NAMESPACE_TRAINING, TRAINING_CM, "training"))
    _create(lab, _configmap(NAMESPACE_PRODUCTION, PRODUCTION_CM, "production"))
    _create(lab, _service_account(NAMESPACE_TRAINING, TRAINING_SA))
    _create(lab, _service_account(NAMESPACE_PRODUCTION, PRODUCTION_SA))

    training_subject = (NAMESPACE_TRAINING, TRAINING_SA)
    production_subject = (NAMESPACE_PRODUCTION, PRODUCTION_SA)
    def review_four():
        return {
            "training_own": _review(lab, training_subject, NAMESPACE_TRAINING, TRAINING_CM),
            "training_cross": _review(lab, training_subject, NAMESPACE_PRODUCTION, PRODUCTION_CM),
            "production_own": _review(lab, production_subject, NAMESPACE_PRODUCTION, PRODUCTION_CM),
            "production_cross": _review(lab, production_subject, NAMESPACE_TRAINING, TRAINING_CM),
        }

    def wait_rbac(expected):
        deadline = time.monotonic() + 25
        while True:
            result = review_four()
            if any(item["evaluationError"] for item in result.values()):
                lab.block(f"Authorization API returned evaluation errors: {result}")
            allowed = {name for name, item in result.items() if item["allowed"]}
            if allowed == expected:
                return result
            if time.monotonic() >= deadline:
                lab.block(f"Expected scoped RBAC decisions did not become active: {result}")
            time.sleep(0.5)

    red = wait_rbac(set())
    red_ok = not any(item["allowed"] for item in red.values())
    lab.check("red", "Both fixed subjects lack access to the application-owned references before grants",
              red_ok, red)

    for namespace, configmap, service_account in (
            (NAMESPACE_TRAINING, TRAINING_CM, TRAINING_SA),
            (NAMESPACE_PRODUCTION, PRODUCTION_CM, PRODUCTION_SA)):
        _create(lab, _role(namespace, configmap))
        _create(lab, _role_binding(namespace, service_account))

    green = wait_rbac({"training_own", "production_own"})
    green_ok = (green["training_own"]["allowed"] and green["production_own"]["allowed"]
                and not green["training_cross"]["allowed"]
                and not green["production_cross"]["allowed"]
                and not any(value["evaluationError"] for value in green.values()))
    lab.check("green", "Namespace-scoped Roles allow each fixed subject its own named reference and deny both cross-environment reads",
              green_ok, green)

    rejected = _pod("saf-0905-012-cross-reference", NAMESPACE_PRODUCTION,
                    PRODUCTION_SA, TRAINING_CM)
    allowed = _pod("saf-0905-012-valid-inference", NAMESPACE_PRODUCTION,
                   PRODUCTION_SA, PRODUCTION_CM)
    before = _server_dry_run(lab, rejected)
    lab.check("red", "The same cross-environment inference Pod structure is admitted before policy enrollment",
              before.returncode == 0, {"returncode": before.returncode,
                                       "stderr": before.stderr.strip()})

    lab.create(_admission_policy())
    lab.create(_admission_binding())
    deadline = time.monotonic() + 25
    while True:
        after = _server_dry_run(lab, rejected)
        if _is_policy_denial(after):
            break
        if after.returncode != 0 or time.monotonic() >= deadline:
            lab.block(f"Expected production policy response did not become active: {after.stderr.strip()}")
        time.sleep(0.5)
    lab.check("green", "Production admission denies the training ConfigMap volume for the stated policy reason",
              _is_policy_denial(after), {"returncode": after.returncode,
                                         "policy_denial": _is_policy_denial(after),
                                         "stderr": after.stderr.strip()})

    positive = _server_dry_run(lab, allowed)
    lab.check("positive", "A valid inference Pod using its own synthetic production reference remains admissible",
              positive.returncode == 0, {"returncode": positive.returncode,
                                        "stderr": positive.stderr.strip()})

    _create(lab, allowed)
    pod = allowed["metadata"]["name"]
    lab.kubectl("-n", NAMESPACE_PRODUCTION, "wait", "--for=jsonpath={.status.phase}=Succeeded",
                f"pod/{pod}", "--timeout=90s", timeout=100)
    observed = lab.kubectl("-n", NAMESPACE_PRODUCTION, "logs", pod).stdout.strip()
    lab.check("positive", "The stored inference Pod completes and reads the expected inert production reference",
              observed == "app://synthetic/production/input-v1", {"read_reference": observed})
