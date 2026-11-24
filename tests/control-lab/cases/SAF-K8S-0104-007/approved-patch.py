"""Bind a disposable emergency patch rehearsal to an attributed approval."""
import json
from pathlib import Path
from runpy import run_path
import time


NS = "saf-test"
NAME = "emergency-patch-ticket"
APPROVER = "fixture-duty-approver"
EXECUTOR = "fixture-patch-executor"


def subject(name):
    return f"system:serviceaccount:{NS}:{name}"


def ticket(lab):
    return json.loads(lab.kubectl("get", "configmap", NAME, "-o", "json").stdout)


def patch(lab, actor):
    return lab.kubectl("patch", "configmap", NAME, "--as", subject(actor), "--type=merge",
                       "--patch", json.dumps({"data": {"decision": "approved", "approver": subject(actor)}}),
                       "-o", "json", allow_failure=True)


def authorized(observed, scope):
    return all(observed.get(field) == expected for field, expected in scope.items()) and (
        observed.get("decision") == "approved" and observed.get("approver") == subject(APPROVER)
    )


def run(lab):
    helper = Path(__file__).resolve().parents[1] / "SAF-K8S-1007-011" / "native-upgrade.py"
    native = run_path(str(helper))
    scope = {"change_id": "fixture-emergency-patch-007", "baseline": native["BASELINE"],
             "target": native["TARGET"], "component_digest": native["image_ref"]("kube-apiserver"),
             "environment": "owned-disposable-kind", "impact_record": "fixture-impact-reviewed",
             "trigger": "fixture-urgent-supported-patch"}
    baseline = lab.kubectl("get", "--raw=/version").stdout
    if json.loads(baseline)["gitVersion"] != scope["baseline"]:
        lab.block("The observed baseline does not match the emergency patch request")
    opened = lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME},
                         "data": {**scope, "decision": "pending"}})
    for role in (APPROVER, EXECUTOR):
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": role}})
    api = "rbac.authorization.k8s.io/v1"
    lab.create({"apiVersion": api, "kind": "Role", "metadata": {"name": APPROVER},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [NAME],
                           "verbs": ["get", "patch"]}]})
    lab.create({"apiVersion": api, "kind": "RoleBinding", "metadata": {"name": APPROVER},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": APPROVER},
                "subjects": [{"kind": "ServiceAccount", "name": APPROVER, "namespace": NS}]})

    forged = patch(lab, EXECUTOR)
    denied = forged.returncode != 0 and "Forbidden" in forged.stderr and subject(EXECUTOR) in forged.stderr
    lab.check("red", "Pending emergency patch and executor self-approval cannot authorize activation",
              not authorized(ticket(lab)["data"], scope) and denied,
              {"pending_blocked": not authorized(opened["data"], scope), "executor_patch_denied_by_rbac": denied})

    approved = patch(lab, APPROVER)
    deadline = time.monotonic() + 20
    while approved.returncode and time.monotonic() < deadline:
        time.sleep(0.5)
        approved = patch(lab, APPROVER)
    live = ticket(lab)
    exact = approved.returncode == 0 and authorized(live["data"], scope)
    rejects_changed_artifact = not authorized(live["data"], {**scope, "component_digest": "fixture-other-image"})
    same_request = live["metadata"]["uid"] == opened["metadata"]["uid"]
    lab.check("green", "The authorized role approves only the exact patch and original ticket",
              exact and rejects_changed_artifact and same_request,
              {"record_approved_by_authorized_fixture_role": exact,
               "different_artifact_denied": rejects_changed_artifact, "same_ticket": same_request})

    native["run_native_upgrade"](lab)
    result = json.loads((lab.evidence / "native-upgrade.raw.json").read_text())
    present = ticket(lab)
    closed = (present["metadata"]["uid"] == opened["metadata"]["uid"]
              and present["data"] == live["data"]
              and result["target_server"] == scope["target"]
              and result["post_upgrade_etcd_recovery"]["restored_exact_uid_and_data"]
              and all(result["post_recovery_checks"].values()))
    lab.check("positive", "The original approval and release match the verified patch and recovery evidence",
              closed, {"same_scoped_approval": present["data"] == live["data"],
                       "target_and_workload_recovery_evidence_matched": closed})
