"""Verify reviewed emergency restoration access to a synthetic backup record."""

import json
import time

SCOPE = "Live Kubernetes authorization for emergency fixture records, with a modeled approval clock."
NS = "saf-test"
RBAC = "rbac.authorization.k8s.io"
ROLE = "fixture-temporary-backup-read"
SUBJECT = "fixture-emergency-operator"
REVIEWER = "fixture-recovery-approver"
TARGET = "fixture-restore-target"
NEIGHBOR = "fixture-restore-neighbor"
MARKER = "fixture backup marker"


def binding(lab, approval):
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "RoleBinding",
                "metadata": {"name": ROLE, "annotations": {"fixture.example/approval": approval}},
                "roleRef": {"apiGroup": RBAC, "kind": "Role", "name": ROLE},
                "subjects": [{"apiGroup": RBAC, "kind": "User", "name": SUBJECT}]})


def reconcile(lab, receipt, now, *, installed=False):
    valid = (receipt["requester"] == SUBJECT and receipt["reviewer"] == REVIEWER
             and receipt["target"] == TARGET and receipt["operation"] == "get"
             and receipt["trigger"] == "approved-recovery-exercise"
             and receipt["start"] <= now < receipt["expires"]
             and 0 < receipt["expires"] - receipt["start"] <= 20)
    if valid and not installed:
        binding(lab, receipt["id"])
    if installed and not valid:
        lab.kubectl("delete", "rolebinding", ROLE)
    return valid


def read(lab, name):
    return lab.kubectl("--as", SUBJECT, "get", "configmap", name, "-o", "json", allow_failure=True)


def see(lab, expected):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        result = read(lab, TARGET)
        if expected and result.returncode == 0:
            return json.loads(result.stdout)["data"]["marker"] == MARKER
        if not expected and result.returncode != 0 and "Forbidden" in result.stderr:
            return True
        time.sleep(0.4)
    lab.block("The API did not converge to the expected backup marker authorization")


def run(lab):
    for name in (TARGET, NEIGHBOR):
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                    "immutable": True, "data": {"marker": MARKER}})
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "Role", "metadata": {"name": ROLE},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [TARGET], "verbs": ["get"]}]})
    binding(lab, "fixture-unconditional-baseline")
    broad = see(lab, True)
    lab.kubectl("delete", "rolebinding", ROLE)
    initially_closed = see(lab, False)
    lab.check("red", "A standing grant exposes the marker without an active review", broad and initially_closed,
              {"standing_grant_readable": broad, "marker_closed_after_baseline": initially_closed})

    receipt = {"id": "fixture-exercise-01", "requester": SUBJECT, "reviewer": REVIEWER,
               "target": TARGET, "operation": "get", "trigger": "approved-recovery-exercise",
               "start": 20, "expires": 30}
    denied = {
        "self_approval": not reconcile(lab, dict(receipt, reviewer=SUBJECT), 21),
        "wrong_target": not reconcile(lab, dict(receipt, target=NEIGHBOR), 21),
        "outside_window": not reconcile(lab, receipt, 19),
        "oversized_window": not reconcile(lab, dict(receipt, expires=60), 21),
    }
    prior_closed = see(lab, False)
    lab.check("green", "The reviewed workflow withholds API access until scoped independent approval is current",
              all(denied.values()) and prior_closed, {**denied, "actual_access_closed": prior_closed})

    issued = reconcile(lab, receipt, 21)
    intended = see(lab, True)
    neighbor = read(lab, NEIGHBOR)
    scoped = neighbor.returncode != 0 and "Forbidden" in neighbor.stderr
    expired = not reconcile(lab, receipt, 30, installed=True) and see(lab, False)
    lab.check("positive", "A current approval permits only its fixture marker and expiry withdraws permission",
              issued and intended and scoped and expired,
              {"reviewed_marker_readable": intended, "unrelated_marker_forbidden": scoped, "after_expiry_denied": expired})
    (lab.evidence / "emergency-backup-access-observations.json").write_text(json.dumps({
        "preapproval": denied, "active_scoped_read": issued and intended and scoped, "expired_access_denied": expired,
        "time_modeled": True, "repository_or_restore_tested": False,
    }, indent=2) + "\n")
