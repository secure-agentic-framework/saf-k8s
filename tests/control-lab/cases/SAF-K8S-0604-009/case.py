"""Exercise contextual remediation deadlines and exception expiry through Kind Jobs."""
from copy import deepcopy
import json
from pathlib import Path
import time

from fixtures import BUSYBOX_IMAGE, container

HERE = Path(__file__).resolve().parent
PYTHON = ("docker.io/library/python:3.13-slim@sha256:"
          "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
POLICY = {"revision": "synthetic-sla-v1", "exception_approvers": ["fixture-duty-reviewer"], "targets": {
    "priority": {"priority": 1, "hours": 4, "owner": "platform-oncall"},
    "triage": {"priority": 2, "hours": 8, "owner": "security-triage"},
    "inference": {"priority": 3, "hours": 12, "owner": "inference-platform"},
    "training": {"priority": 4, "hours": 72, "owner": "training-platform"},
}}
OPENED = "2026-01-01T00:00:00+00:00"
FIRST = "2026-01-01T12:00:00+00:00"
LATER = "2026-01-01T13:00:00+00:00"
SCOPE = (
    "A disposable Kind cluster runs an auditable remediation deadline engine against "
    "fictional findings. Reviewed purpose is tied to the exact workload artifact. "
    "The versioned fixture policy uses deterministic clocks to exercise incomplete "
    "context, exception authorization and expiry, and verified resolution."
)


def observe(lab, tier, kind):
    name = f"sla-context-{tier}"
    pod = {"automountServiceAccountToken": False, "containers": [
        container("marker", command=["sh", "-c", f"echo {name}"]),
    ]}
    labels = {"app": name}
    template = {"metadata": {"labels": labels}, "spec": pod}
    if kind == "Job":
        pod["restartPolicy"] = "Never"
        spec = {"template": template, "backoffLimit": 0}
        group = "batch/v1"
    else:
        spec = {"replicas": 1, "selector": {"matchLabels": labels}, "template": template}
        pod["containers"][0]["command"] = ["sh", "-c", "sleep 180"]
        group = "apps/v1"
    work = lab.create({"apiVersion": group, "kind": kind, "metadata": {"name": name}, "spec": spec})
    condition = "Complete" if kind == "Job" else "Available"
    lab.kubectl("wait", f"--for=condition={condition}", f"{kind.lower()}/{name}", "--timeout=60s", timeout=70)
    result = json.loads(lab.kubectl("get", kind.lower(), name, "-o", "json").stdout)
    same_identity = result["metadata"]["uid"] == work["metadata"]["uid"] and result["kind"] == kind
    return {"context": tier, "artifact": result["spec"]["template"]["spec"]["containers"][0]["image"],
            "owner_observed": same_identity, "workload_uid": result["metadata"]["uid"]}


def record(name, findings):
    input_file = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                  "immutable": True, "data": {part: json.dumps(value, sort_keys=True) for part, value in findings.items()}}
    return input_file


def run_check(lab, name, findings_name, at):
    inputs = [{"configMap": {"name": "sla-policy"}}, {"configMap": {"name": findings_name}}]
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 85, "template": {"spec": {
            "automountServiceAccountToken": False, "restartPolicy": "Never",
            "containers": [{
                "name": "review", "image": PYTHON, "command": ["python", "-B", "/fixture/schedule.py", at],
                "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
            }],
            "volumes": [{"name": "fixture", "projected": {"sources": inputs}}],
        }}},
    })
    deadline = time.monotonic() + 95
    while time.monotonic() < deadline:
        result = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)
        status = next((entry["type"] for entry in result.get("status", {}).get("conditions", [])
                       if entry["status"] == "True" and entry["type"] in {"Complete", "Failed"}), None)
        if status:
            logs = lab.kubectl("logs", f"job/{name}").stdout
            pods = json.loads(lab.kubectl("get", "pod", "-l", f"job-name={name}", "-o", "json").stdout)["items"]
            pod, = pods
            code = pod["status"]["containerStatuses"][0]["state"]["terminated"]["exitCode"]
            return status, code, json.loads(logs)
        time.sleep(1)
    lab.block("The deadline verification Job did not terminate")


def run(lab):
    inventory = {"inference": observe(lab, "inference", "Deployment"),
                 "training": observe(lab, "training", "Job")}

    def item(name, workload, severity, **attributes):
        return {"id": name, "workload": workload, "base_severity": severity, "opened": OPENED,
                "security_signal": "routine", "artifact": BUSYBOX_IMAGE, **attributes}

    priority = item("training-signal", "training", 7)
    priority["security_signal"] = "priority-review"
    priority["exception"] = {"finding": priority["id"], "artifact": BUSYBOX_IMAGE,
                             "approver": "fixture-duty-reviewer", "start": OPENED, "expires": LATER}
    unmatched = item("unknown-artifact", "inference", 5, verification={
        "at": "2026-01-01T06:00:00+00:00", "artifact": BUSYBOX_IMAGE, "reviewed": True,
    })
    unmatched["artifact"] = BUSYBOX_IMAGE.split("@")[0] + "@sha256:" + "f" * 64
    inference_overdue = item("inference-overdue", "inference", 7)
    inference_overdue["exception"] = {**priority["exception"], "finding": inference_overdue["id"],
                                     "approver": "fixture-unapproved-requester"}
    baseline = [item("routine-training", "training", 9), inference_overdue, priority, unmatched]
    severity_only = [entry["id"] for entry in sorted(baseline, key=lambda entry: -entry["base_severity"])]
    lab.check("red", "Severity alone places the routine training finding first and assigns no deadlines",
              severity_only[0] == "routine-training", {"severity_only_first": severity_only[0]})
    policy_map = record("sla-policy", {"policy.json": POLICY})
    policy_map["data"]["schedule.py"] = (HERE / "schedule.py").read_text()
    lab.create(policy_map)
    lab.create(record("sla-findings", {"findings.json": {"workloads": inventory, "findings": baseline}}))
    failed, first_exit, first = run_check(lab, "sla-before-expiry", "sla-findings", FIRST)
    initial = first["decisions"]
    chosen = first["ordered"] == ["training-signal", "unknown-artifact", "inference-overdue", "routine-training"]
    remains = failed == "Failed" and first_exit == 23 and first["blockers"] == ["unknown-artifact", "inference-overdue"]
    classified = initial["unknown-artifact"]["owner"] == "security-triage"
    bad_exception_ignored = initial["inference-overdue"]["disposition"] == "overdue"
    lab.check("green", "Context changes risk order and imposes a triage deadline for an unmatched artifact",
              chosen and remains and classified and bad_exception_ignored,
              {"context_order": chosen, "overdue_gate": remains,
               "unknown_routed_for_triage": classified, "unauthorized_deferral_ignored": bad_exception_ignored})
    state, later_exit, later = run_check(lab, "sla-after-expiry", "sla-findings", LATER)
    now_overdue = initial["training-signal"]["disposition"] == "approved-deferral" and (
        later["decisions"]["training-signal"]["disposition"] == "overdue" and
        later["decisions"]["training-signal"]["due"] == initial["training-signal"]["due"])
    lab.check("green", "An approved deferral expires at its boundary without extending the original target",
              state == "Failed" and later_exit == 23 and now_overdue,
              {"exception_expired": now_overdue, "original_target_preserved": now_overdue})

    updated = deepcopy(baseline)
    for finding in updated:
        if finding["id"] != "routine-training":
            finding["verification"] = {"artifact": finding["artifact"], "at": "2026-01-01T12:30:00+00:00",
                                       "reviewed": True}
    lab.create(record("sla-verified-findings", {"findings.json": {"workloads": inventory, "findings": updated}}))
    resolved, resolved_exit, last = run_check(lab, "sla-released", "sla-verified-findings", LATER)
    late = all(last["decisions"][key]["disposition"] == "remediated-late"
               for key in ("training-signal", "inference-overdue", "unknown-artifact"))
    audit = {"initial": first, "after_expiry": later, "verified_remediation": last}
    lab.create(record("sla-audit", {"audit.json": audit}))
    saved = json.loads(lab.kubectl("get", "configmap", "sla-audit", "-o", "json").stdout)
    retained = saved["immutable"] and json.loads(saved["data"]["audit.json"]) == audit
    lab.check("positive", "Matching verified remediation clears the gate and keeps the overdue history",
              resolved == "Complete" and resolved_exit == 0 and last["blockers"] == [] and late and retained,
              {"released_after_verification": resolved == "Complete", "late_history_preserved": late and retained})
    (lab.evidence / "sla-decisions.json").write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n")
