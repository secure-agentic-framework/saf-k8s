"""Exercise an attributable stage-approval handoff in the owned namespace."""

import json
import re
import subprocess
import time


NS = "saf-test"
LABEL = "saf-k8s.example/feature-review"
APPROVAL = "fixture-scoped-beta-approval"
PREFIX = "fixture-feature-change-"
UPDATE = "fixture-feature-review-evidence-writes"
CREATE = "fixture-feature-activation"
CHANGE_MESSAGE = "feature change lacks current approval for its exact scope"
UPDATE_MESSAGE = "approval record update must come from its assigned actor"
PLATFORM = "fixture-platform-review"
SECURITY = "fixture-security-review"
ROLLOUT = "fixture-approved-rollout"
FIELDS = ("feature", "stage", "component", "build", "image_digest", "scope", "desired",
          "origin", "risk_assessment", "expires_on")


def user(name):
    return f"system:serviceaccount:{NS}:{name}"


def resource(name, data):
    return {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "data": data}


def grant(lab):
    for name in (PLATFORM, SECURITY, ROLLOUT):
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": name}})
    api = "rbac.authorization.k8s.io/v1"
    lab.create({"apiVersion": api, "kind": "Role", "metadata": {"name": CREATE}, "rules": [
        {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["create"]},
        {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [APPROVAL],
         "verbs": ["get", "patch"]},
    ]})
    lab.create({"apiVersion": api, "kind": "RoleBinding", "metadata": {"name": CREATE},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": CREATE},
                "subjects": [{"kind": "ServiceAccount", "name": name, "namespace": NS}
                             for name in (PLATFORM, SECURITY, ROLLOUT)]})


def install(lab, name, operation, match, expression, message, *, params=False):
    api = "admissionregistration.k8s.io/v1"
    spec = {
        "failurePolicy": "Fail",
        "matchConstraints": {"resourceRules": [
            {"apiGroups": [""], "apiVersions": ["v1"], "operations": [operation],
             "resources": ["configmaps"]},
        ]},
        "matchConditions": [{"name": "owned-fixture", "expression": match}],
        "validations": [{"expression": expression, "message": message, "reason": "Forbidden"}],
    }
    binding = {"policyName": name, "validationActions": ["Deny"],
               "matchResources": {"namespaceSelector": {"matchLabels": {LABEL: "enabled"}}}}
    if params:
        spec["paramKind"] = {"apiVersion": "v1", "kind": "ConfigMap"}
        binding["paramRef"] = {"name": APPROVAL, "namespace": NS, "parameterNotFoundAction": "Deny"}
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": name}, "spec": spec})
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding",
                "metadata": {"name": name}, "spec": binding})


def plan(lab, data, name="proposal", *, dry_run=True):
    flags = ["--dry-run=server"] if dry_run else []
    return lab.kubectl("create", "--as", user(ROLLOUT), *flags, "-f", "-", "-o", "json",
                       payload=json.dumps(resource(PREFIX + name, data)), allow_failure=True)


def patch(lab, actor, fields):
    return lab.kubectl("patch", "configmap", APPROVAL, "--as", user(actor), "--type=merge",
                       "--patch", json.dumps({"data": fields}), "-o", "json", allow_failure=True)


def rejected(result, message):
    return result.returncode != 0 and message in result.stderr


def current_gates(lab):
    result = subprocess.run(
        ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
         "--request-timeout=20s", "get", "--raw=/metrics"],
        capture_output=True, text=True, env=lab.env, timeout=25,
    )
    if result.returncode:
        lab.block("Unable to read the owned API server's selected metrics")
    gates = {}
    for line in result.stdout.splitlines():
        if not line.startswith("kubernetes_feature_enabled{"):
            continue
        match = re.fullmatch(r"kubernetes_feature_enabled\{([^}]+)\}\s+([01](?:\.0+)?)", line)
        if match:
            labels = dict(re.findall(r'(\w+)="([^"]*)"', match[1]))
            if labels.get("name") in {"ContainerStopSignals", "PodLevelResources"}:
                gates[labels["name"]] = {"active": float(match[2]) == 1, "stage": labels.get("stage")}
    return gates


def run(lab):
    effective = current_gates(lab)
    lab.check("positive", "The stock API server separately exposes alpha-off and beta-on effective states",
              effective == {"ContainerStopSignals": {"active": False, "stage": "ALPHA"},
                            "PodLevelResources": {"active": True, "stage": "BETA"}}, effective)
    version = json.loads(lab.kubectl("version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    pod = json.loads(lab.kubectl("get", "pod", f"kube-apiserver-{lab.cluster}-control-plane",
                                 "-n", "kube-system", "-o", "json").stdout)
    image = next(status["imageID"] for status in pod["status"]["containerStatuses"]
                 if status["name"] == "kube-apiserver")
    match = re.search(r"sha256:[a-f0-9]{64}$", image)
    if version != "v1.36.1" or not match:
        lab.block("The pinned API server must have an observed component build and image digest")
    data = {"feature": "PodLevelResources", "stage": "Beta", "component": "kube-apiserver",
            "build": version, "image_digest": match[0], "origin": "version-default",
            "scope": "owned-fixture", "desired": "true", "risk_assessment": "fixture-risk-023",
            "expires_on": "2026-12-15"}
    lab.create(resource(APPROVAL, {**data, "platform": "pending", "security": "pending"}))
    grant(lab)
    response = plan(lab, data)
    deadline = time.monotonic() + 20
    while response.returncode and time.monotonic() < deadline:
        time.sleep(0.5)
        response = plan(lab, data)
    lab.check("red", "The candidate plan reaches the API before any reviewed-approval constraint",
              response.returncode == 0, {"baseline_plan_admitted": response.returncode == 0})

    fixed = " && ".join(f"oldObject.data['{key}'] == object.data['{key}']" for key in FIELDS)
    rule = (
        "(" + fixed + ") && (("
        f"request.userInfo.username == '{user(PLATFORM)}' && object.data.platform == 'approved' "
        "&& oldObject.data.platform == 'pending' && object.data.security == oldObject.data.security) || ("
        f"request.userInfo.username == '{user(SECURITY)}' && object.data.platform == oldObject.data.platform && "
        "((oldObject.data.security == 'pending' && object.data.security == 'approved') || "
        "(oldObject.data.security == 'approved' && object.data.security == 'revoked'))))"
    )
    install(lab, UPDATE, "UPDATE", f"object.metadata.name == '{APPROVAL}'", rule, UPDATE_MESSAGE)
    exact = " && ".join(f"'{key}' in object.data && object.data['{key}'] == params.data['{key}']" for key in FIELDS)
    condition = (
        f"request.userInfo.username == '{user(ROLLOUT)}' && params != null "
        f"&& has(object.data) && ({exact}) && params.data.platform == 'approved' "
        "&& params.data.security == 'approved' "
        "&& timestamp(params.data.expires_on + 'T00:00:00Z') > timestamp('2026-11-21T00:00:00Z')"
    )
    install(lab, CREATE, "CREATE", f"object.metadata.name.startsWith('{PREFIX}')",
            condition, CHANGE_MESSAGE, params=True)
    deadline = time.monotonic() + 20
    response = plan(lab, data)
    while not rejected(response, CHANGE_MESSAGE) and time.monotonic() < deadline:
        time.sleep(0.5)
        response = plan(lab, data)
    unapproved = rejected(response, CHANGE_MESSAGE)
    forged = rejected(patch(lab, ROLLOUT, {"platform": "approved", "security": "approved"}), UPDATE_MESSAGE)
    lab.check("green", "Current beta defaults do not authorize a plan and the requester cannot self-approve",
              unapproved and forged, {"unapproved_plan_denied": unapproved, "forged_approval_denied": forged})

    if patch(lab, PLATFORM, {"platform": "approved"}).returncode != 0:
        lab.block("The designated platform reviewer could not record its own review")
    one_review = rejected(plan(lab, data), CHANGE_MESSAGE)
    if patch(lab, SECURITY, {"security": "approved"}).returncode != 0:
        lab.block("The designated security reviewer could not record its own review")
    deadline = time.monotonic() + 20
    allowed = plan(lab, data).returncode == 0
    while not allowed and time.monotonic() < deadline:
        time.sleep(0.5)
        allowed = plan(lab, data).returncode == 0
    stored = plan(lab, data, name="approved", dry_run=False)
    persisted = stored.returncode == 0 and json.loads(stored.stdout)["data"] == data
    mismatch = {
        "wrong_component": rejected(plan(lab, {**data, "component": "kubelet"}, "wrong-component"), CHANGE_MESSAGE),
        "wrong_origin": rejected(plan(lab, {**data, "origin": "explicit"}, "wrong-origin"), CHANGE_MESSAGE),
        "wrong_image": rejected(plan(lab, {**data, "image_digest": "sha256:" + "0" * 64}, "wrong-image"),
                                CHANGE_MESSAGE),
    }
    lab.check("positive", "Both distinct reviewers authorize only the exact feature change plan",
              one_review and allowed and persisted and all(mismatch.values()),
              {"one_review_denied": one_review, "both_reviews_admit_exact_plan": allowed, "approved_plan_persisted": persisted,
               **mismatch})
    if patch(lab, SECURITY, {"security": "revoked"}).returncode != 0:
        lab.block("The designated security reviewer could not revoke its review")
    deadline = time.monotonic() + 20
    revoked = rejected(plan(lab, data, "after-revocation"), CHANGE_MESSAGE)
    while not revoked and time.monotonic() < deadline:
        time.sleep(0.5)
        revoked = rejected(plan(lab, data, "after-revocation"), CHANGE_MESSAGE)
    lab.check("green", "Revoking the security review denies a new matching plan",
              revoked, {"revoked_plan_denied": revoked})
