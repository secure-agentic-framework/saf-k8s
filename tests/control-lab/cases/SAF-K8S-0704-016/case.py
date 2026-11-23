"""Observe a full scoped entitlement reconciliation through the live authorizer."""

import json
import time

SCOPE = "Actual Kubernetes RBAC drift detection, remediation, and post-change authorization for an owned fixture."
RBAC = "rbac.authorization.k8s.io"
TARGET = "drift-fixture-marker"
BASELINE = "unrelated-fixture-marker"
DESIRED = "fixture-review-current"
STALE = "fixture-review-retired"
UNAFFECTED = "fixture-review-unrelated"


def group_subject(group):
    return {"kind": "Group", "apiGroup": RBAC, "name": group}


def add_scope(lab, name, group):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                "data": {"marker": name}})
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "Role", "metadata": {"name": name},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [name],
                           "verbs": ["get"]}]})
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "RoleBinding", "metadata": {"name": name},
                "roleRef": {"apiGroup": RBAC, "kind": "Role", "name": name}, "subjects": [group_subject(group)]})


def binding_subject(lab, name):
    binding = json.loads(lab.kubectl("get", "rolebinding", name, "-o", "json").stdout)
    return binding["subjects"]


def can_read(lab, group, name):
    result = lab.kubectl("--as", f"user-{group}", "--as-group", group,
                         "get", "configmap", name, "-o", "json", allow_failure=True)
    if result.returncode == 0:
        if json.loads(result.stdout)["data"]["marker"] != name:
            lab.block("Authorized fixture read returned unexpected content")
        return True
    if "(Forbidden)" not in result.stderr or name not in result.stderr:
        lab.block("The fixture authorization decision was not an observed allow or forbid")
    return False


def observed(lab):
    return {"approved_subject_allowed": can_read(lab, DESIRED, TARGET),
            "stale_subject_allowed": can_read(lab, STALE, TARGET),
            "unrelated_grant_allowed": can_read(lab, UNAFFECTED, BASELINE),
            "approved_subject_allowed_unrelated_object": can_read(lab, DESIRED, BASELINE)}


def run(lab):
    add_scope(lab, TARGET, STALE)
    add_scope(lab, BASELINE, UNAFFECTED)
    desired = [group_subject(DESIRED)]
    recorded_before = binding_subject(lab, TARGET)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        before = observed(lab)
        if before["stale_subject_allowed"] and before["unrelated_grant_allowed"]:
            break
        time.sleep(0.4)
    expected_before = {"approved_subject_allowed": False, "stale_subject_allowed": True,
                       "unrelated_grant_allowed": True, "approved_subject_allowed_unrelated_object": False}
    lab.check("red", "Stored binding and live access reveal both the stale grant and missing approved grant",
              recorded_before == [group_subject(STALE)] and before == expected_before, before)

    lab.kubectl("patch", "rolebinding", TARGET, "--type=merge", "-p", json.dumps({"subjects": desired}))
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        after = observed(lab)
        if after["approved_subject_allowed"] and not after["stale_subject_allowed"]:
            break
        time.sleep(0.4)
    reconciled = binding_subject(lab, TARGET) == desired
    lab.check("green", "Replacing the owned stale binding subject restores approved access and revokes stale access",
              reconciled and after["approved_subject_allowed"] and not after["stale_subject_allowed"],
              {"binding_matches_approved_subject": reconciled, "approved_subject_allowed": after["approved_subject_allowed"],
               "stale_subject_allowed": after["stale_subject_allowed"]})
    unchanged = binding_subject(lab, BASELINE) == [group_subject(UNAFFECTED)]
    lab.check("positive", "The unrelated grant still works and the corrected subject cannot read that unrelated object",
              unchanged and after["unrelated_grant_allowed"] and not after["approved_subject_allowed_unrelated_object"],
              {"unrelated_binding_unchanged": unchanged, "unrelated_grant_allowed": after["unrelated_grant_allowed"],
               "approved_subject_allowed_unrelated_object": after["approved_subject_allowed_unrelated_object"]})
    evidence = {"expected_external_inventory_is_synthetic": True, "before": before, "after": after,
                "binding_matches_approved_subject": reconciled, "unrelated_binding_unchanged": unchanged}
    (lab.evidence / "entitlement-drift-observations.json").write_text(json.dumps(evidence, indent=2) + "\n")
