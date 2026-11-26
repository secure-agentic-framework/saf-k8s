"""Observe a full scoped entitlement reconciliation through the live authorizer."""

import json
import time
from pathlib import Path

SCOPE = "Actual Kubernetes RBAC drift detection, remediation, and post-change authorization for an owned fixture."
RBAC = "rbac.authorization.k8s.io"
TARGET = "drift-fixture-marker"
BASELINE = "unrelated-fixture-marker"
DESIRED = "fixture-review-current"
STALE = "fixture-review-retired"
UNAFFECTED = "fixture-review-unrelated"
REVIEWER = "entitlement-reviewer"
UNAPPROVED_REVIEWER = "entitlement-unapproved"
POLICY = "approved-entitlement"
IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
         "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
ROOT = Path(__file__).resolve().parent


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


def setup_reviewer(lab):
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": REVIEWER}})
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": UNAPPROVED_REVIEWER}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": POLICY},
                "immutable": True,
                "data": {"approved-entitlement.json": json.dumps({
                    "target": TARGET, "unrelated_binding": BASELINE,
                    "approved_group": DESIRED, "stale_group": STALE,
                    "policy_version": "synthetic-review-v1"}),
                         "reconcile.py": (ROOT / "reconcile.py").read_text()}})
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "Role", "metadata": {"name": REVIEWER},
                "rules": [{"apiGroups": [RBAC], "resources": ["rolebindings"],
                           "resourceNames": [TARGET], "verbs": ["get", "patch"]},
                          {"apiGroups": [RBAC], "resources": ["roles"],
                           "resourceNames": [TARGET], "verbs": ["bind"]}]})
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "RoleBinding", "metadata": {"name": REVIEWER},
                "roleRef": {"apiGroup": RBAC, "kind": "Role", "name": REVIEWER},
                "subjects": [{"kind": "ServiceAccount", "namespace": "saf-test", "name": REVIEWER}]})


def run_job(lab, name, account, operation):
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                "spec": {"activeDeadlineSeconds": 70, "backoffLimit": 0, "template": {"spec": {
                    "restartPolicy": "Never", "serviceAccountName": account,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{"name": "review", "image": IMAGE,
                                    "command": ["python", "/fixture/reconcile.py", operation],
                                    "securityContext": {"allowPrivilegeEscalation": False,
                                                        "readOnlyRootFilesystem": True,
                                                        "capabilities": {"drop": ["ALL"]}},
                                    "volumeMounts": [{"name": "policy", "mountPath": "/fixture",
                                                      "readOnly": True}]}],
                    "volumes": [{"name": "policy", "configMap": {"name": POLICY}}],
                }}}})
    lab.kubectl("wait", "--for=condition=Complete", f"job/{name}", "--timeout=80s", timeout=90)
    return json.loads(lab.kubectl("logs", f"job/{name}").stdout)


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
    setup_reviewer(lab)
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

    target_before_reconcile = json.loads(lab.kubectl("get", "rolebinding", TARGET, "-o", "json").stdout)
    baseline_before_reconcile = json.loads(lab.kubectl("get", "rolebinding", BASELINE, "-o", "json").stdout)
    policy_before_reconcile = json.loads(lab.kubectl("get", f"configmap/{POLICY}", "-o", "json").stdout)
    authorized = run_job(lab, "entitlement-reconcile", REVIEWER, "reconcile")
    target_after_authorized = json.loads(lab.kubectl("get", "rolebinding", TARGET, "-o", "json").stdout)
    unauthorized = run_job(lab, "entitlement-deny-target", UNAPPROVED_REVIEWER, "deny-target")
    boundary = run_job(lab, "entitlement-deny-boundaries", REVIEWER, "deny-scope-policy")
    target_after_reconcile = json.loads(lab.kubectl("get", "rolebinding", TARGET, "-o", "json").stdout)
    baseline_after_reconcile = json.loads(lab.kubectl("get", "rolebinding", BASELINE, "-o", "json").stdout)
    policy_after_reconcile = json.loads(lab.kubectl("get", f"configmap/{POLICY}", "-o", "json").stdout)
    remediation_authorized = (authorized["http_status"] == 200 and authorized["persisted"] is True
                              and authorized["resource_version_changed"] is True
                              and target_before_reconcile["subjects"] == [group_subject(STALE)]
                              and target_after_authorized["metadata"]["resourceVersion"]
                              != target_before_reconcile["metadata"]["resourceVersion"]
                              and target_after_authorized["subjects"] == desired)
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
    boundary_safe = (unauthorized["http_status"] == 403 and unauthorized["denied"] is True
                     and boundary["unrelated_http_status"] == 403 and boundary["unrelated_denied"] is True
                     and boundary["policy_http_status"] == 403 and boundary["policy_denied"] is True
                     and baseline_after_reconcile["metadata"]["resourceVersion"]
                     == baseline_before_reconcile["metadata"]["resourceVersion"]
                     and policy_after_reconcile["metadata"]["resourceVersion"]
                     == policy_before_reconcile["metadata"]["resourceVersion"]
                     and policy_after_reconcile["data"] == policy_before_reconcile["data"])
    unauthorized_left_target_unchanged = (
        target_after_reconcile["metadata"]["resourceVersion"]
        == target_after_authorized["metadata"]["resourceVersion"]
        and target_after_reconcile["subjects"] == target_after_authorized["subjects"])
    lab.check("green", "The reconciliation identity is limited to its approved target and policy",
              remediation_authorized and boundary_safe and unauthorized_left_target_unchanged,
              {"authorized_remediation_persisted": remediation_authorized,
               "unapproved_writer_denied": unauthorized["http_status"] == 403,
               "unrelated_binding_write_denied": boundary["unrelated_http_status"] == 403,
               "policy_write_denied": boundary["policy_http_status"] == 403,
               "unrelated_binding_unchanged": baseline_after_reconcile["metadata"]["resourceVersion"]
               == baseline_before_reconcile["metadata"]["resourceVersion"],
               "policy_unchanged": policy_after_reconcile["metadata"]["resourceVersion"]
               == policy_before_reconcile["metadata"]["resourceVersion"],
               "target_unchanged_after_denied_probe": unauthorized_left_target_unchanged})
    evidence = {"expected_external_inventory_is_synthetic": True, "before": before, "after": after,
                "binding_matches_approved_subject": reconciled, "unrelated_binding_unchanged": unchanged,
                "reviewer_authorized_update_persisted": remediation_authorized,
                "unapproved_target_write_denied": unauthorized["http_status"] == 403,
                "unrelated_binding_and_policy_write_denied": boundary_safe,
                "target_unchanged_after_denied_probe": unauthorized_left_target_unchanged}
    (lab.evidence / "entitlement-drift-observations.json").write_text(json.dumps(evidence, indent=2) + "\n")
