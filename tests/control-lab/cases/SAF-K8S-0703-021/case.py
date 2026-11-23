"""Verify positive admission and quota policy with an owned synthetic resource."""

import json
import time

SCOPE = "Scoped Pod CREATE admission and namespace quota for a synthetic accelerator slot in Kind."
IMAGE = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
SLOT = "saf.example/accelerator-slot"
QUOTA_KEY = "requests." + SLOT
POLICY = "saf-fixture-accelerator"
RULE = "fixture accelerator requires the authorized principal and approved resource declaration"
PREFIX = "system:serviceaccount:saf-test:"
APPROVED = "accelerator-submitter"
OTHER = "ordinary-submitter"


def pod(name):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "fixture", "image": IMAGE, "command": ["/bin/sleep", "180"],
                        "resources": {"requests": {SLOT: "1", "cpu": "5m", "memory": "4Mi"},
                                      "limits": {SLOT: "1", "cpu": "100m", "memory": "24Mi"}},
                        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]}}}]}}


def submit(lab, payload, user, *, dry=True):
    flags = ("--dry-run=server",) if dry else ()
    return lab.kubectl("--as", PREFIX + user, "create", "-f", "-", "-o", "json", *flags,
                       payload=json.dumps(payload), allow_failure=True)


def wait(lab, predicate, diagnostic, *, seconds=50):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(1)
    lab.block(diagnostic)


def get(lab, kind, name):
    return json.loads(lab.kubectl("get", kind, name, "-o", "json").stdout)


def add_roles(lab):
    for user in (APPROVED, OTHER):
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": user},
                    "automountServiceAccountToken": False})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "fixture-submit"},
                "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "fixture-submit"},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "fixture-submit"},
                "subjects": [{"kind": "ServiceAccount", "namespace": "saf-test", "name": user}
                             for user in (APPROVED, OTHER)]})


def apply_policy(lab):
    expression = (f"request.userInfo.username == '{PREFIX}{APPROVED}' && "
                  "object.spec.containers.exists(c, has(c.resources) && has(c.resources.requests) && "
                  f"has(c.resources.limits) && '{SLOT}' in c.resources.requests && '{SLOT}' in c.resources.limits)")
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
                "metadata": {"name": POLICY}, "spec": {"failurePolicy": "Fail", "matchConstraints": {"resourceRules": [
                    {"operations": ["CREATE"], "apiGroups": [""], "apiVersions": ["v1"], "resources": ["pods"],
                     "scope": "Namespaced"}]}, "validations": [{"expression": expression, "message": RULE}]}})
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
                "metadata": {"name": POLICY}, "spec": {"policyName": POLICY, "validationActions": ["Deny"],
                    "matchResources": {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "saf-test"}}}}})


def declined(result):
    return result.returncode != 0 and POLICY in result.stderr and RULE in result.stderr


def run(lab):
    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    if len(nodes) != 1 or not nodes[0]["metadata"]["name"].startswith(lab.cluster + "-"):
        lab.block("The fixture requires exactly one owned Kind node")
    node = nodes[0]["metadata"]["name"]
    patch = json.dumps([{"op": "add", "path": "/status/capacity/" + SLOT.replace("/", "~1"), "value": "2"}])
    lab.kubectl("patch", "node", node, "--subresource=status", "--type=json", "-p", patch)
    wait(lab, lambda: get(lab, "node", node)["status"]["allocatable"].get(SLOT) == "2",
         "Synthetic node capacity did not become allocatable", seconds=70)
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    add_roles(lab)
    lab.create({"apiVersion": "v1", "kind": "ResourceQuota", "metadata": {"name": "fixture-accelerators"},
                "spec": {"hard": {QUOTA_KEY: "1"}}})
    quota_used = lambda: get(lab, "resourcequota", "fixture-accelerators").get("status", {}).get("used", {}).get(QUOTA_KEY)
    wait(lab, lambda: quota_used() == "0", "ResourceQuota did not start accounting")
    ordinary = pod("ordinary-identity")
    before = submit(lab, ordinary, OTHER)
    lab.check("red", "Namespace Pod creation and quota alone accept a valid fixture request in a dry run",
              before.returncode == 0, {"comparison_request_admitted": before.returncode == 0})
    apply_policy(lab)
    wait(lab, lambda: declined(submit(lab, ordinary, OTHER)), "Fixture admission policy did not converge")
    missing = pod("missing-declaration")
    for kind in ("requests", "limits"):
        del missing["spec"]["containers"][0]["resources"][kind][SLOT]
    incomplete = declined(submit(lab, missing, APPROVED))
    lab.check("green", "Admission requires the approved principal and an explicit synthetic resource declaration",
              incomplete and quota_used() == "0", {"other_principal_denied": True, "missing_declaration_denied": incomplete})
    accepted = submit(lab, pod("approved-one"), APPROVED, dry=False)
    if accepted.returncode != 0:
        lab.block("The approved request did not create its fixture Pod; inspect the command log")
    lab.kubectl("wait", "--for=condition=Ready", "pod/approved-one", "--timeout=70s", timeout=80)
    wait(lab, lambda: quota_used() == "1", "ResourceQuota did not account for the admitted fixture")
    charged = get(lab, "pod", "approved-one")
    resources = charged["spec"]["containers"][0]["resources"]
    scheduled = (charged["spec"]["nodeName"] == node and resources["requests"][SLOT] == resources["limits"][SLOT] == "1")
    lab.check("positive", "The approved Pod reaches Ready on the synthetic node and consumes one quota unit",
              scheduled, {"right_resource_scheduled": scheduled, "namespace_quota_used": 1})
    over = submit(lab, pod("over-quota"), APPROVED)
    denied_quota = over.returncode != 0 and "exceeded quota" in over.stderr and QUOTA_KEY in over.stderr
    lab.check("green", "Namespace quota denies a second valid request while the node still advertises two slots",
              denied_quota and quota_used() == "1", {"quota_denial_verified": denied_quota, "node_slots": 2})
    (lab.evidence / "resource-admission-observations.json").write_text(json.dumps({
        "approved_synthetic_resource": SLOT, "principal_check": True, "quota_verified": denied_quota,
        "admitted_and_scheduled": scheduled, "capacity": 2, "quota": 1,
    }, indent=2) + "\n")
