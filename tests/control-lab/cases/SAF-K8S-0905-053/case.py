"""Exercise a real CronJob allowlist review and acceptance of scheduled retries."""
from datetime import datetime
import json
from pathlib import Path
import time

HERE = Path(__file__).parent
PYTHON = "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
NAME = "model-source-review"
POLICY = "model-source-allowlist"
DECISIONS = "model-source-review-decisions"
CYCLE = "fixture-2026-11"
REVIEWED_AT = "2026-11-01T03:00:00Z"
URL = "https://models.example.invalid/saf-fixture/"
PRIOR = [{"id": ident, "source": URL + path, "publisher": "fixture-team"}
         for ident, path in (("keep", "alpha"), ("rename", "old-name"), ("revoke", "revoked"), ("stale", "stale"))]
REVIEW = {"cycle": CYCLE, "reviewed_at": REVIEWED_AT, "reviewer": "fixture-security",
          "approver": "fixture-governance",
          "decisions": {
              "keep": {"status": "approved", "reason": "publisher-remains-approved"},
              "rename": {"status": "approved", "source": URL + "new-name", "reason": "independently-reviewed-rename"},
              "revoke": {"status": "revoked", "reason": "publisher-approval-withdrawn"},
          }}
SCOPE = (
    "A real UTC CronJob controller in disposable Kubernetes v1.36.1 schedules two review "
    "Jobs under a restricted ServiceAccount. Inert decisions model monthly revalidation. "
    "The Kubernetes object stores the updated allowlist and decision record in one update, "
    "with exact timestamps and CronJob owner evidence collected independently. The test "
    "uses a one-minute accelerated cadence and verifies a repeat run is idempotent. Actual "
    "organization review timing, source ownership and trust, audit retention and consumer "
    "rollout remain open."
)


def _cm(lab, name, values, *, immutable=False):
    return lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                       "immutable": immutable, "data": values})


def _setup(lab):
    _cm(lab, POLICY, {"approved.json": json.dumps(PRIOR), "history.json": "[]"})
    _cm(lab, DECISIONS, {"review.json": json.dumps(REVIEW)}, immutable=True)
    _cm(lab, "review-worker", {"worker.py": (HERE / "worker.py").read_text()}, immutable=True)
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": NAME}})
    lab.create({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": NAME},
        "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [DECISIONS], "verbs": ["get"]},
                  {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [POLICY], "verbs": ["get", "update"]}],
    })
    lab.create({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": NAME},
        "subjects": [{"kind": "ServiceAccount", "name": NAME, "namespace": "saf-test"}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": NAME},
    })
    pod = {
        "serviceAccountName": NAME, "restartPolicy": "Never",
        "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{
            "name": "review", "image": PYTHON, "command": ["python", "-B", "/case/worker.py"],
            "volumeMounts": [{"name": "worker", "mountPath": "/case", "readOnly": True}],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "15m", "memory": "32Mi"},
                          "limits": {"cpu": "200m", "memory": "96Mi"}},
        }],
        "volumes": [{"name": "worker", "configMap": {"name": "review-worker"}}],
    }
    return lab.create({
        "apiVersion": "batch/v1", "kind": "CronJob", "metadata": {"name": NAME},
        "spec": {"schedule": "* * * * *", "timeZone": "Etc/UTC", "concurrencyPolicy": "Forbid",
                 "startingDeadlineSeconds": 45, "suspend": True, "successfulJobsHistoryLimit": 3,
                 "jobTemplate": {"spec": {"backoffLimit": 1, "activeDeadlineSeconds": 50,
                                          "template": {"spec": pod}}}},
    })


def _policy(lab):
    raw = json.loads(lab.kubectl("get", f"configmap/{POLICY}", "-o", "json").stdout)["data"]
    return json.loads(raw["approved.json"]), json.loads(raw["history.json"])


def _jobs(lab, parent):
    raw = json.loads(lab.kubectl("get", "jobs", "-o", "json").stdout)["items"]
    jobs = []
    for item in raw:
        metadata = item["metadata"]
        if not any(entry.get("uid") == parent and entry.get("kind") == "CronJob" and entry.get("controller")
                   for entry in metadata.get("ownerReferences", [])):
            continue
        phase = {x["type"] for x in item.get("status", {}).get("conditions", []) if x["status"] == "True"}
        if "Failed" in phase:
            lab.kubectl("logs", "job/" + metadata["name"], allow_failure=True)
            lab.block("Controller-scheduled review failed")
        start = metadata.get("annotations", {}).get("batch.kubernetes.io/cronjob-scheduled-timestamp")
        if not start:
            lab.block("Controller Job has no scheduled timestamp")
        jobs.append((start, metadata["name"], "Complete" in phase))
    return sorted(jobs)


def _complete(lab, parent, count):
    deadline = time.monotonic() + 145
    while time.monotonic() < deadline:
        jobs = _jobs(lab, parent)
        if len(jobs) >= count and all(row[2] for row in jobs[:count]):
            return jobs[:count]
        time.sleep(2)
    lab.block("Timed out waiting for controller-owned review Jobs")


def _set_suspend(lab, suspend):
    lab.kubectl("patch", f"cronjob/{NAME}", "--type=merge",
                "-p", json.dumps({"spec": {"suspend": suspend}}))


def _verify_decisions(lab, policy, events):
    expected = [{**PRIOR[0], "reviewed_at": REVIEWED_AT},
                {**PRIOR[1], "source": URL + "new-name", "reviewed_at": REVIEWED_AT}]
    expected_event = {
        "cycle": CYCLE, "reviewed_at": REVIEWED_AT, "reviewer": "fixture-security", "approver": "fixture-governance",
        "decisions": [
            {"id": "keep", "action": "keep", "old_source": URL + "alpha",
             "current_source": URL + "alpha", "reason": "publisher-remains-approved"},
            {"id": "rename", "action": "update", "old_source": URL + "old-name",
             "current_source": URL + "new-name", "reason": "independently-reviewed-rename"},
            {"id": "revoke", "action": "remove", "old_source": URL + "revoked",
             "reason": "publisher-approval-withdrawn"},
            {"id": "stale", "action": "remove", "old_source": URL + "stale", "reason": "no-current-review"},
        ],
    }
    lab.check("green", "The scheduled review commits the exact revised policy and records all decisions",
              policy == expected and events == [expected_event],
              {"allowlist_matches": policy == expected, "history_matches": events == [expected_event],
               "approved_ids": [row["id"] for row in policy]})


def run(lab):
    cron = _setup(lab)
    owner = cron["metadata"]["uid"]
    before, empty_history = _policy(lab)
    lab.check("red", "A suspended review leaves stale and revoked entries on the old allowlist",
              before == PRIOR and empty_history == [] and _jobs(lab, owner) == [],
              {"prior_ids": [row["id"] for row in before], "history_count": len(empty_history)})
    _set_suspend(lab, False)
    first, = _complete(lab, owner, 1)
    updated, history = _policy(lab)
    _verify_decisions(lab, updated, history)
    first, second = _complete(lab, owner, 2)
    _set_suspend(lab, True)
    after, later_history = _policy(lab)
    first_time, second_time = (datetime.fromisoformat(row[0].replace("Z", "+00:00")) for row in (first, second))
    outcomes = [json.loads(lab.kubectl("logs", "job/" + job[1]).stdout)["outcome"] for job in (first, second)]
    good_order = (second_time - first_time).total_seconds() == 60
    unchanged = after == updated and later_history == history
    lab.check("positive", "Two controller-owned review Jobs run one minute apart and preserve one decision record",
              good_order and unchanged and outcomes == ["updated", "already-recorded"],
              {"interval_matches_fixture_schedule": good_order, "same_policy_and_history": unchanged,
               "job_outcomes": outcomes, "retained_events": len(later_history)})
    account = f"--as=system:serviceaccount:saf-test:{NAME}"
    writer = lab.kubectl("auth", "can-i", "update", "configmap/" + POLICY, account).stdout.strip()
    approval = lab.kubectl("auth", "can-i", "update", "configmap/" + DECISIONS, account,
                           allow_failure=True).stdout.strip()
    lab.check("positive", "The scheduled identity updates the allowlist and has no authority to revise approval input",
              writer == "yes" and approval == "no", {"allowlist_update": writer, "decision_update": approval})
    (lab.evidence / "model-source-review.json").write_text(json.dumps(
        {"cron_uid": owner, "timeZone": cron["spec"]["timeZone"], "jobs": [first, second],
         "before": before, "after": after, "history": later_history, "checks": lab.checks}, indent=2) + "\n")
