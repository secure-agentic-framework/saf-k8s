"""Exercise namespace-scoped VAP enforcement for Secret-backed env injection."""
import json
import time
from pathlib import Path


SCOPE = (
    "Kubernetes v1.36 native ValidatingAdmissionPolicy against inert, case-owned "
    "fixtures. Direct Pod CREATE checks normal and init containers for env[]."
    "valueFrom.secretKeyRef and envFrom[].secretRef; the ephemeral-container "
    "matrix uses the explicit pods/ephemeralcontainers subresource. A separate "
    "Deployment-template VAP is tested. Namespace selector scoping, ConfigMap "
    "environment injection, and a Secret volume mount are positive boundaries. "
    "No Secret data values are created, read, or emitted."
)

NAMESPACE = "saf-0403-029-fixtures"
OUTSIDE_NAMESPACE = "saf-0403-029-outside"
SECRET_NAME = "saf-0403-029-empty-secret"
CONFIGMAP_NAME = "saf-0403-029-inert-config"
DENY_MARKER = "SAF-K8S-0403-029:"
POD_POLICY = "saf-k8s-0403-029-pod-env-secret"
DEPLOYMENT_POLICY = "saf-k8s-0403-029-deployment-env-secret"
IMAGE = "registry.k8s.io/pause:3.10"


def _container(name, injection=None):
    result = {"name": name, "image": IMAGE}
    if injection == "env":
        result["env"] = [{
            "name": "SAF_INERT_FIXTURE",
            "valueFrom": {"secretKeyRef": {"name": SECRET_NAME, "key": "missing-in-empty-secret"}},
        }]
    elif injection == "envFrom":
        result["envFrom"] = [{"secretRef": {"name": SECRET_NAME}}]
    return result


def _pod(name, location="normal", injection=None, namespace=NAMESPACE):
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"restartPolicy": "Never", "containers": [_container("main")]},
    }
    if location == "normal":
        pod["spec"]["containers"] = [_container("main", injection)]
    elif location == "init":
        pod["spec"]["initContainers"] = [_container("init", injection)]
    return pod


def _deployment(name, injection=None):
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": {
            "replicas": 0,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {"containers": [_container("main", injection)]},
            },
        },
    }


def _apply(lab, obj, phase, scenario, denied=False, expected_marker=DENY_MARKER):
    result = lab.kubectl("create", "-f", "-", "-o", "name", "-n", obj["metadata"]["namespace"],
                         payload=json.dumps(obj), allow_failure=True)
    accepted = result.returncode == 0
    has_policy_marker = expected_marker in result.stderr
    correct = (not accepted and has_policy_marker) if denied else accepted
    lab.check(
        phase,
        f"{scenario} is {'denied by the scoped policy' if denied else 'accepted'}",
        correct,
        {
            "request_reached_api": accepted or has_policy_marker,
            "admission_outcome": "accepted" if accepted else "denied",
            "policy_denial_marker": has_policy_marker,
            "expected_policy_denial": denied,
        },
    )
    return accepted


def _delete(lab, resource, name, namespace=NAMESPACE):
    lab.kubectl("delete", resource, name, "-n", namespace,
                "--ignore-not-found=true", "--wait=true", "--timeout=15s")


def _ephemeral_patch(lab, name, injection, denied):
    container = _container("debug", injection)
    patch = {"spec": {"ephemeralContainers": [container]}}
    result = lab.kubectl(
        "patch", f"pod/{name}", "-n", NAMESPACE, "--subresource=ephemeralcontainers",
        "--type=merge", "-p", json.dumps(patch), "-o", "name",
        allow_failure=True,
    )
    accepted = result.returncode == 0
    has_policy_marker = DENY_MARKER in result.stderr
    correct = (not accepted and has_policy_marker) if denied else accepted
    lab.check(
        "green" if denied else "red",
        f"ephemeralcontainers subresource {injection} request is "
        f"{'denied by the scoped policy' if denied else 'accepted before policy'}",
        correct,
        {
            "request_resource": "pods/ephemeralcontainers",
            "request_operation": "UPDATE",
            "admission_outcome": "accepted" if accepted else "denied",
            "policy_denial_marker": has_policy_marker,
            "expected_policy_denial": denied,
        },
    )


def _check_policy_type(lab, name):
    deadline = time.monotonic() + 30
    status = {}
    while time.monotonic() < deadline:
        policy = json.loads(lab.kubectl("get", "validatingadmissionpolicy", name, "-o", "json").stdout)
        status = policy.get("status", {})
        if "typeChecking" in status and status.get("observedGeneration") == policy["metadata"]["generation"]:
            break
        time.sleep(0.25)
    summary = {
        "type_check_completed": "typeChecking" in status,
        "warnings": len(status.get("typeChecking", {}).get("expressionWarnings", [])),
        "observed_current_generation": status.get("observedGeneration") == policy["metadata"]["generation"],
    }
    lab.check("positive", f"{name} is type checked without warnings",
              summary["type_check_completed"] and summary["observed_current_generation"]
              and summary["warnings"] == 0, summary)


def _wait_for_binding(lab, manifest, marker):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        result = lab.kubectl(
            "create", "-n", NAMESPACE, "--dry-run=server", "-f", "-", "-o", "name",
            payload=json.dumps(manifest), allow_failure=True,
        )
        if result.returncode and marker in result.stderr:
            return
        if result.returncode:
            lab.block(f"Unexpected API error while probing the binding for {manifest['kind']}")
        time.sleep(0.25)
    lab.block(f"The deny binding did not match the known invalid {manifest['kind']} request")


def run(lab):
    case_dir = Path(__file__).parent
    # All referenced objects are empty or inert; no Secret data key/value exists.
    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl("create", "namespace", OUTSIDE_NAMESPACE)
    lab.kubectl("label", "namespace", NAMESPACE,
                "saf-k8s-0403-029-enforce=true", "--overwrite")
    lab.kubectl("create", "secret", "generic", SECRET_NAME, "-n", NAMESPACE)
    lab.kubectl("create", "configmap", CONFIGMAP_NAME, "-n", NAMESPACE)
    lab.kubectl("create", "secret", "generic", SECRET_NAME, "-n", OUTSIDE_NAMESPACE)

    matrix = [("normal", "env"), ("normal", "envFrom"),
              ("init", "env"), ("init", "envFrom")]

    # Red baseline: submit and delete the fixtures while enforcement is absent.
    # The green phase recreates these exact names and payload shapes.
    for location, injection in matrix:
        name = f"case-{location}-{injection.lower()}"
        _apply(lab, _pod(name, location, injection), "red",
               f"Pod {location} container {injection}")
        _delete(lab, "pod", name)
    _apply(lab, _deployment("case-deployment", "envFrom"), "red",
           "Deployment template envFrom.secretRef")
    _delete(lab, "deployment", "case-deployment")

    # Ephemeral containers are added only through the named API subresource.
    for injection in ("env", "envFrom"):
        name = f"case-ephemeral-{injection.lower()}"
        _apply(lab, _pod(name), "red", f"ephemeral base Pod for {injection}")
        _ephemeral_patch(lab, name, injection, denied=False)
        _delete(lab, "pod", name)

    lab.apply(case_dir / "admission-policy.yaml")
    for policy in (POD_POLICY, DEPLOYMENT_POLICY):
        _check_policy_type(lab, policy)
    _wait_for_binding(lab, _pod("pod-policy-readiness", "normal", "env"),
                      "SAF-K8S-0403-029: Secret references in container")
    _wait_for_binding(lab, _deployment("deployment-policy-readiness", "envFrom"),
                      "SAF-K8S-0403-029: Secret references in Deployment")

    # Green: recreate the same class of fixtures. Each matching negative must
    # carry the unique VAP message, distinguishing it from unrelated rejection.
    for location, injection in matrix:
        name = f"case-{location}-{injection.lower()}"
        _apply(lab, _pod(name, location, injection), "green",
               f"Pod {location} container {injection}", denied=True)
    for injection in ("env", "envFrom"):
        name = f"case-ephemeral-{injection.lower()}"
        _apply(lab, _pod(name), "positive", f"ephemeral base Pod for {injection}")
        _ephemeral_patch(lab, name, injection, denied=True)

    _apply(lab, _deployment("case-deployment", "envFrom"), "green",
           "Deployment template envFrom.secretRef", denied=True,
           expected_marker="SAF-K8S-0403-029: Secret references in Deployment")

    # Permitted counterpart: ConfigMap envFrom plus a Secret volume reference.
    # The Secret exists but is empty, so neither object stores a credential.
    positive = _pod("permitted-configmap-and-secret-volume")
    positive["spec"]["containers"][0]["envFrom"] = [
        {"configMapRef": {"name": CONFIGMAP_NAME}}
    ]
    positive["spec"]["volumes"] = [{
        "name": "inert-secret-volume", "secret": {"secretName": SECRET_NAME}
    }]
    positive["spec"]["containers"][0]["volumeMounts"] = [
        {"name": "inert-secret-volume", "mountPath": "/var/run/inert-secret", "readOnly": True}
    ]
    _apply(lab, positive, "positive",
           "ConfigMap environment source and empty Secret volume reference")

    # Selector boundary: same secret-backed env configuration in an unlabeled
    # namespace must be accepted. This is a scope assertion, not a policy pass.
    _apply(lab, _pod("outside-scope-secret-env", "normal", "envFrom", OUTSIDE_NAMESPACE),
           "positive", "same Pod request in unlabeled namespace")
