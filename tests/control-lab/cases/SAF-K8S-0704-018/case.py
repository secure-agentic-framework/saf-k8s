"""Verify the authorized lifecycle of temporary fixture access in Kubernetes."""

import json
import time

SCOPE = "A synthetic two-person approval record with live namespaced access activation and revocation."
API = "rbac.authorization.k8s.io/v1"
NAME = "emergency-fixture-read"
TARGET = "emergency-fixture-marker"
OUTSIDE = "emergency-fixture-other"
USER = "fixture-emergency-requester"
RUN_ID = "emergency-fixture-window"
ROLE_GROUP = "rbac.authorization.k8s.io"


def allowed(lab, name):
    decision = lab.create({"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview",
                           "spec": {"user": USER, "groups": ["system:authenticated"], "resourceAttributes": {
                               "namespace": "saf-test", "verb": "get", "resource": "configmaps", "name": name}}})["status"]
    if decision.get("evaluationError"):
        lab.block("The authorization review reported an evaluation error")
    return decision.get("allowed", False)


def approval_valid(record, slot):
    approvers = set(record["approvers"])
    return len(approvers) == 2 and record["requester"] not in approvers and record["start"] <= slot < record["end"]


def reconcile(lab, record, slot, active):
    approved = approval_valid(record, slot)
    if approved and not active:
        lab.create({"apiVersion": API, "kind": "RoleBinding",
                    "metadata": {"name": NAME, "annotations": {"fixture.example/approval": RUN_ID}},
                    "roleRef": {"apiGroup": ROLE_GROUP, "kind": "Role", "name": NAME},
                    "subjects": [{"apiGroup": ROLE_GROUP, "kind": "User", "name": record["requester"]}]})
    if active and not approved:
        lab.kubectl("delete", "rolebinding", NAME)
    return approved


def observe(lab, expected):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        decision = allowed(lab, TARGET)
        if decision is expected:
            return decision
        time.sleep(0.4)
    lab.block("The live authorizer did not converge to the expected fixture decision")


def actual_read(lab, name):
    result = lab.kubectl("--as", USER, "get", "configmap", name, "-o", "json", allow_failure=True)
    if result.returncode == 0:
        marker = json.loads(result.stdout).get("data", {}).get("marker")
        if marker != name:
            lab.block("The emergency fixture read returned unexpected content")
        return "allowed"
    if "(Forbidden)" not in result.stderr or name not in result.stderr:
        lab.block("The actual emergency request did not return a named authorization denial")
    return "forbidden"


def run(lab):
    for name in (TARGET, OUTSIDE):
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "data": {"marker": name}})
    lab.create({"apiVersion": API, "kind": "Role", "metadata": {"name": NAME},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [TARGET], "verbs": ["get"]}]})
    record = {"id": RUN_ID, "requester": USER, "approvers": ["fixture-reviewer-one"], "start": 10, "end": 20}
    rejected = not reconcile(lab, record, 15, False)
    prior = allowed(lab, TARGET)
    actual_before = actual_read(lab, TARGET)
    lab.check("red", "One approval leaves the owned emergency marker denied by Kubernetes", rejected and not prior,
              {"approval_rejected": rejected, "marker_allowed": prior})

    record["approvers"].append("fixture-reviewer-two")
    active = reconcile(lab, record, 15, False)
    live = observe(lab, True)
    comparison = allowed(lab, OUTSIDE)
    actual_active = actual_read(lab, TARGET)
    actual_outside = actual_read(lab, OUTSIDE)
    binding = json.loads(lab.kubectl("get", "rolebinding", NAME, "-o", "json").stdout)
    traceable = binding["metadata"]["annotations"]["fixture.example/approval"] == RUN_ID
    lab.check("green", "Two approvals activate the exact owned marker read and the live binding links to the approval",
              active and live and not comparison and traceable,
              {"approved_marker_allowed": live, "outside_marker_allowed": comparison, "approval_link_matches": traceable})

    expired = not reconcile(lab, record, 20, active)
    final = observe(lab, False)
    actual_after_expiry = actual_read(lab, TARGET)
    binding_removed = not lab.kubectl("get", "rolebinding", NAME, "--ignore-not-found", "-o", "name").stdout.strip()
    lab.check("positive", "At the fixture window expiry, the binding is removed and Kubernetes denies the read again",
              expired and not final and binding_removed,
              {"expired": expired, "marker_allowed_after_expiry": final, "binding_removed": binding_removed})
    live_request_ok = (actual_before == "forbidden" and actual_active == "allowed"
                       and actual_outside == "forbidden" and actual_after_expiry == "forbidden")
    lab.check("green", "Actual API requests follow the scoped emergency window and deny the outside marker",
              live_request_ok,
              {"before_activation": actual_before, "approved_target_during_window": actual_active,
               "outside_target_during_window": actual_outside, "target_after_expiry": actual_after_expiry})
    result = {"fixture_clock": True, "approval": record, "before": prior, "active": live, "outside": comparison,
              "after": final, "binding_removed": binding_removed, "approval_link_matches": traceable,
              "actual_before": actual_before, "actual_active": actual_active,
              "actual_outside": actual_outside, "actual_after_expiry": actual_after_expiry}
    (lab.evidence / "emergency-window-observations.json").write_text(json.dumps(result, indent=2) + "\n")
