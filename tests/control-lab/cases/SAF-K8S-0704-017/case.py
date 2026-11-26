"""Verify that effective Kubernetes authorization stays within the owned allowlist."""

import json
import time

SCOPE = (
    "Live authorization reviews and actual owned ConfigMap reads for a synthetic "
    "identity with two additive namespaced RBAC grants before and after remediation. "
    "The held API permissions are separate from actual cloud identity authentication."
)
API = "rbac.authorization.k8s.io/v1"
USER = "fixture-boundary-reviewer"
MARKER = "boundary-approved"
EXTRA = "boundary-other"
NAMESPACE = "saf-test"


def grant(lab, name, rules):
    lab.create({"apiVersion": API, "kind": "Role", "metadata": {"name": name}, "rules": rules})
    lab.create({"apiVersion": API, "kind": "RoleBinding", "metadata": {"name": name},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name},
                "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": USER}]})


def allowed(lab, verb, resource, *, name="", group="", namespace=NAMESPACE):
    review = lab.create({"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview",
                         "spec": {"user": USER, "groups": ["system:authenticated"], "resourceAttributes": {
                             "verb": verb, "group": group, "resource": resource, "name": name, "namespace": namespace}}})
    status = review["status"]
    if status.get("evaluationError"):
        lab.block("The authorization review reported an evaluation error")
    return status.get("allowed", False)


def matrix(lab):
    return {"approved_marker": allowed(lab, "get", "configmaps", name=MARKER),
            "other_marker": allowed(lab, "get", "configmaps", name=EXTRA),
            "different_namespace": allowed(lab, "get", "configmaps", name=MARKER, namespace="saf-comparison"),
            "enlarge_grant": allowed(lab, "create", "rolebindings", group="rbac.authorization.k8s.io"),
            "read_secrets": allowed(lab, "get", "secrets", name="nonexistent-owned-comparison")}


def actual_read(lab, name):
    result = lab.kubectl("--as", USER, "get", "configmap", name, "-o", "json", allow_failure=True)
    if result.returncode == 0:
        value = json.loads(result.stdout).get("data", {}).get("marker")
        if value != name:
            lab.block("The actual fixture API read returned unexpected content")
        return "allowed"
    if "(Forbidden)" not in result.stderr or name not in result.stderr:
        lab.block("The actual fixture request did not return a named authorization denial")
    return "forbidden"


def run(lab):
    lab.kubectl("create", "namespace", "saf-comparison")
    for name in (MARKER, EXTRA):
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "data": {"marker": name}})
    grant(lab, "boundary-approved", [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [MARKER], "verbs": ["get"]}])
    grant(lab, "boundary-extra", [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [EXTRA], "verbs": ["get"]}])
    expected = {"approved_marker": True, "other_marker": False, "different_namespace": False,
                "enlarge_grant": False, "read_secrets": False}
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        before = matrix(lab)
        if before["approved_marker"] and before["other_marker"]:
            break
        time.sleep(0.4)
    lab.check("red", "The second owned grant produces an effective allow outside the approved matrix",
              before == dict(expected, other_marker=True), before)
    extra_before = actual_read(lab, EXTRA)
    lab.kubectl("delete", "rolebinding", "boundary-extra")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        after = matrix(lab)
        if not after["other_marker"]:
            break
        time.sleep(0.4)
    lab.check("green", "Removing the extra binding restores the exact reviewed authorization matrix", after == expected, after)
    read = lab.kubectl("--as", USER, "get", "configmap", MARKER, "-o", "json")
    actual = json.loads(read.stdout)["data"]["marker"]
    lab.check("positive", "The approved owned ConfigMap remains readable through the live request", actual == MARKER,
              {"approved_marker_read_succeeded": actual == MARKER})
    extra_after = actual_read(lab, EXTRA)
    lab.check("green", "An actual request to the extra marker changes from allowed to forbidden after cleanup",
              extra_before == "allowed" and extra_after == "forbidden",
              {"extra_marker_before": extra_before, "extra_marker_after": extra_after})
    (lab.evidence / "boundary-observations.json").write_text(json.dumps(
        {"before": before, "after": after, "approved_marker_read_succeeded": actual == MARKER,
         "extra_marker_actual_request_before": extra_before,
         "extra_marker_actual_request_after": extra_after,
         "synthetic_identity": True}, indent=2) + "\n")
