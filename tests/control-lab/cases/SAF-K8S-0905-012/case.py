"""Demonstrate bounded training/production separation with Kubernetes APIs."""
import json
import subprocess
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


def _worker_script(namespace, own_cm, other_namespace, other_cm, expected_reference):
    """Return a fixed script; it reports only status and a boolean, never token/body errors."""
    return f'''import json, ssl, time, urllib.error, urllib.request
token = open("/var/run/projected/token", encoding="utf-8").read().strip()
ctx = ssl.create_default_context(cafile="/var/run/projected/ca.crt")
def get(ns, name):
    req = urllib.request.Request(
        "https://kubernetes.default.svc/api/v1/namespaces/" + ns + "/configmaps/" + name,
        headers={{"Authorization": "Bearer " + token}},
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=8) as response:
            status = response.status
            data = json.loads(response.read())
            match = data.get("data", {{}}).get("reference") == {expected_reference!r}
    except urllib.error.HTTPError as exc:
        status, match = exc.code, False
    except Exception:
        status, match = 0, False
    return status, match
own_status, own_match = get({namespace!r}, {own_cm!r})
other_status, _ = get({other_namespace!r}, {other_cm!r})
print(json.dumps({{"own_status": own_status, "own_reference_matches": own_match,
                  "other_status": other_status}}), flush=True)
time.sleep(240)
'''


def _identity_worker(namespace, pod_name, service_account, script_cm):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": pod_name, "namespace": namespace,
                     "labels": {"saf-k8s.example/workload": "projected-identity-fixture"}},
        "spec": {
            "serviceAccountName": service_account,
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "containers": [{"name": "identity-check",
                "image": "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90",
                "command": ["python", "-c", "import runpy; runpy.run_path('/fixture/check.py', run_name='__main__')"],
                "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                              "limits": {"cpu": "100m", "memory": "96Mi"}},
                "volumeMounts": [{"name": "identity", "mountPath": "/var/run/projected", "readOnly": True},
                                 {"name": "script", "mountPath": "/fixture", "readOnly": True}],
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "runAsNonRoot": True, "runAsUser": 1000,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}}}],
            "volumes": [
                {"name": "identity", "projected": {"sources": [
                    {"serviceAccountToken": {"path": "token", "expirationSeconds": 600}},
                    {"configMap": {"name": "kube-root-ca.crt",
                                    "items": [{"key": "ca.crt", "path": "ca.crt"}]}}]}},
                {"name": "script", "configMap": {"name": script_cm,
                    "items": [{"key": "check.py", "path": "check.py"}]}}],
        },
    }


def _private_kubectl(lab, namespace, *args, payload=None):
    """Keep projected bearer values and TokenReview bodies outside runner evidence."""
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
               f"kind-{lab.cluster}", "-n", namespace, "--request-timeout=8s", *args]
    try:
        result = subprocess.run(command, input=payload, text=True, capture_output=True,
                                env=lab.env, timeout=12)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("Private projected-identity observation failed (response suppressed)")
    if result.returncode:
        lab.block("Private projected-identity observation failed (response suppressed)")
    return result.stdout.strip()


def _observe_projected_identity(lab, namespace, pod_name, service_account,
                                own_namespace, own_cm, other_namespace, other_cm,
                                expected_reference):
    # Pod output is a fixed three-field JSON record; raw API payloads and errors are suppressed.
    deadline = time.monotonic() + 45
    result = None
    while time.monotonic() < deadline:
        try:
            result = json.loads(lab.kubectl("-n", namespace, "logs", pod_name).stdout.strip())
            break
        except (json.JSONDecodeError, Exception):
            time.sleep(0.5)
    if not isinstance(result, dict) or set(result) != {
            "own_status", "own_reference_matches", "other_status"}:
        lab.block("Projected-identity worker did not produce its bounded result")

    # Token stdout is captured directly by subprocess and held only in this local variable.
    token = _private_kubectl(lab, namespace, "exec", pod_name, "--", "cat",
                             "/var/run/projected/token")
    if not token or "\n" in token:
        lab.block("Projected identity did not contain one token (value suppressed)")
    review = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
              "spec": {"token": token}}
    try:
        response = json.loads(_private_kubectl(
            lab, namespace, "create", "-f", "-", "-o", "json",
            payload=json.dumps(review)))
    except (json.JSONDecodeError, Exception):
        lab.block("Projected identity TokenReview failed (response suppressed)")
    finally:
        token = None
        review = None
    status = response.get("status", {})
    authenticated = status.get("authenticated") is True
    user = status.get("user", {})
    expected_user = f"system:serviceaccount:{namespace}:{service_account}"
    observed = {
        "authenticated": authenticated,
        "username_matches": authenticated and user.get("username") == expected_user,
        "groups_include_namespace": authenticated and
            f"system:serviceaccounts:{namespace}" in user.get("groups", []),
        "audience_returned": bool(status.get("audiences")),
        "own_get_status": result["own_status"],
        "own_reference_matches": result["own_reference_matches"] is True,
        "cross_namespace_get_status": result["other_status"],
    }
    ok = (observed["authenticated"] and observed["username_matches"]
          and observed["groups_include_namespace"] and observed["audience_returned"]
          and observed["own_get_status"] == 200 and observed["own_reference_matches"]
          and observed["cross_namespace_get_status"] == 403)
    return ok, observed


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

    # Independently exercise actual short-lived projected API credentials in each scope.
    workers = (
        (NAMESPACE_TRAINING, "saf-0905-012-training-identity", TRAINING_SA,
         "saf-0905-012-training-identity-script", TRAINING_CM,
         NAMESPACE_PRODUCTION, PRODUCTION_CM, "app://synthetic/training/input-v1"),
        (NAMESPACE_PRODUCTION, "saf-0905-012-production-identity", PRODUCTION_SA,
         "saf-0905-012-production-identity-script", PRODUCTION_CM,
         NAMESPACE_TRAINING, TRAINING_CM, "app://synthetic/production/input-v1"),
    )
    identity_results = []
    for namespace, pod_name, service_account, script_cm, own_cm, other_namespace, other_cm, reference in workers:
        script = _worker_script(namespace, own_cm, other_namespace, other_cm, reference)
        _create(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                      "metadata": {"name": script_cm, "namespace": namespace},
                      "data": {"check.py": script}})
        _create(lab, _identity_worker(namespace, pod_name, service_account, script_cm))
        lab.kubectl("-n", namespace, "wait", "--for=condition=Ready",
                    f"pod/{pod_name}", "--timeout=60s", timeout=70)
        identity_results.append(_observe_projected_identity(
            lab, namespace, pod_name, service_account, namespace, own_cm,
            other_namespace, other_cm, reference))
    projected_ok = all(ok for ok, _ in identity_results)
    lab.check("positive", "Projected tokens are issued to the actual case ServiceAccounts, authorize their own ConfigMap reads, and deny cross-namespace reads",
              projected_ok, {"training": identity_results[0][1],
                             "production": identity_results[1][1],
                             "token_values_recorded": False,
                             "token_review_errors_recorded": False})
    for namespace, pod_name, _, script_cm, *_ in workers:
        lab.kubectl("-n", namespace, "delete", "pod", pod_name, "--wait=true")
        lab.kubectl("-n", namespace, "delete", "configmap", script_cm, "--wait=true")
