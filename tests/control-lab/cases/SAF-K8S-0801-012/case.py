"""Verify approved same-trust scheduling for a synthetic shared accelerator pool."""

import json
import time

SCOPE = "Kubernetes Pod admission, taint and placement for one declared trust domain on a synthetic sharing pool."
RESOURCE = "fixture.example/shared-accelerator"
LABEL = "fixture.example/shared-trust"
TRUST = "reviewed-group"
POLICY = "fixture-trusted-pool"
MESSAGE = "Fixture shared pool requires approved identity and placement"
APPROVED = "fixture-approved-pool-user"
ORDINARY = "fixture-ordinary-pool-user"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"


def pod(name, *, directed=True):
    spec = {"automountServiceAccountToken": False, "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "fixture", "image": IMAGE, "command": ["python", "-c", "import time; time.sleep(150)"],
                            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                "capabilities": {"drop": ["ALL"]}},
                            "resources": {"limits": {RESOURCE: "1", "cpu": "100m", "memory": "40Mi"},
                                          "requests": {"cpu": "5m", "memory": "12Mi"}}}]}
    if directed:
        spec["nodeSelector"] = {LABEL: TRUST}
        spec["tolerations"] = [{"key": LABEL, "operator": "Equal", "value": TRUST, "effect": "NoSchedule"}]
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": spec}


def submit(lab, user, manifest, *, dry_run=True):
    flags = ["--dry-run=server"] if dry_run else []
    return lab.kubectl("--as", user, "create", "-f", "-", "-o", "json", *flags,
                       payload=json.dumps(manifest), allow_failure=True)


def configure_pool(lab):
    node, = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    name = node["metadata"]["name"]
    lab.kubectl("label", "node", name, f"{LABEL}={TRUST}")
    lab.kubectl("taint", "node", name, f"{LABEL}={TRUST}:NoSchedule")
    path = RESOURCE.replace("/", "~1")
    lab.kubectl("patch", "node", name, "--subresource=status", "--type=json", "-p",
                json.dumps([{"op": "add", "path": f"/status/capacity/{path}", "value": "2"}]))
    return name


def allow_submitters(lab):
    rbac = "rbac.authorization.k8s.io"
    lab.create({"apiVersion": f"{rbac}/v1", "kind": "Role", "metadata": {"name": POLICY},
                "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}]})
    lab.create({"apiVersion": f"{rbac}/v1", "kind": "RoleBinding", "metadata": {"name": POLICY},
                "roleRef": {"apiGroup": rbac, "kind": "Role", "name": POLICY},
                "subjects": [{"apiGroup": rbac, "kind": "User", "name": user} for user in (APPROVED, ORDINARY)]})


def enforce(lab):
    api = "admissionregistration.k8s.io/v1"
    containers = "object.spec.containers + (has(object.spec.initContainers) ? object.spec.initContainers : [])"
    demands_pool = f"variables.containers.exists(c, has(c.resources) && has(c.resources.limits) && '{RESOURCE}' in c.resources.limits)"
    tolerates_pool = f"has(object.spec.tolerations) && object.spec.tolerations.exists(t, !has(t.key) || t.key == '' || t.key == '{LABEL}')"
    pins_pool = f"has(object.spec.nodeSelector) && '{LABEL}' in object.spec.nodeSelector"
    direct_node = "has(object.spec.nodeName) && object.spec.nodeName != ''"
    predicate = (f"!({demands_pool} || ({tolerates_pool}) || ({pins_pool}) || ({direct_node})) || "
                 f"(request.userInfo.username == '{APPROVED}' && ({pins_pool}) && object.spec.nodeSelector['{LABEL}'] == '{TRUST}' "
                 f"&& !({direct_node}) && has(object.spec.tolerations) && object.spec.tolerations.exists(t, "
                 f"has(t.key) && t.key == '{LABEL}' && has(t.operator) && t.operator == 'Equal' "
                 f"&& has(t.value) && t.value == '{TRUST}' && has(t.effect) && t.effect == 'NoSchedule'))")
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail",
                         "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                                "operations": ["CREATE"], "resources": ["pods"]}]},
                         "variables": [{"name": "containers", "expression": containers}],
                         "validations": [{"expression": predicate, "message": MESSAGE}]}})
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"], "matchResources": {
                    "namespaceSelector": {"matchLabels": {"fixture.example/shared-policy": "true"}}}}})


def denied(result):
    return result.returncode != 0 and MESSAGE in result.stderr


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted",
                "fixture.example/shared-policy=true")
    node = configure_pool(lab)
    allow_submitters(lab)
    other = pod("fixture-unapproved")
    admitted_before = submit(lab, ORDINARY, other).returncode == 0
    lab.check("red", "The ordinary user can request the shared pool before eligibility policy is enabled",
              admitted_before, {"unapproved_admitted_before": admitted_before})

    enforce(lab)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if denied(submit(lab, ORDINARY, other)):
            break
        time.sleep(0.45)
    else:
        lab.block("The reviewed admission policy did not deny ordinary shared-pool use")
    without_pool = denied(submit(lab, APPROVED, pod("fixture-undirected", directed=False)))
    pinned = pod("fixture-direct", directed=False)
    pinned["spec"]["nodeName"] = node
    direct_denied = denied(submit(lab, APPROVED, pinned))
    lab.check("green", "Admission rejects unapproved use and approved submissions missing scheduler-mediated placement",
              without_pool and direct_denied, {"ordinary_user_denied": True, "missing_placement_denied": without_pool,
                                              "direct_node_assignment_denied": direct_denied})

    names = ["fixture-approved-one", "fixture-approved-two"]
    for name in names:
        if submit(lab, APPROVED, pod(name), dry_run=False).returncode:
            lab.block("The reviewed approved Pod could not be submitted")
    scheduled = []
    for name in names:
        lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=70s", timeout=80)
        observed = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
        scheduled.append(observed["spec"]["nodeName"] == node)
    lab.check("positive", "Both approved inert workloads run on the same approved model pool node",
              all(scheduled), {"approved_workloads_on_intended_pool": sum(scheduled)})
    (lab.evidence / "shared-pool-observations.json").write_text(json.dumps(
        {"unapproved_admitted_before": admitted_before, "ordinary_user_denied": True,
         "missing_placement_denied": without_pool, "direct_node_assignment_denied": direct_denied,
         "approved_workloads_on_intended_pool": sum(scheduled), "device_sharing_is_synthetic": True}, indent=2) + "\n")
