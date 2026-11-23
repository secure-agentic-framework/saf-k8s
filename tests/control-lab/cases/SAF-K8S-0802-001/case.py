"""Demonstrate staged rollout, effective version evidence, and rollback for a modeled driver."""

import json
import time

SCOPE = "Actual DaemonSet rollout and rollback of inert release markers, with no driver, hardware or host changes."
NAME = "fixture-driver-rollout"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
OLD = "fixture-old-release"
APPROVED = "fixture-approved-release"
REJECTED = "fixture-rejected-candidate"
ENV = "FIXTURE_RELEASE"


def install(lab):
    labels = {"app": NAME}
    lab.create({"apiVersion": "apps/v1", "kind": "DaemonSet", "metadata": {"name": NAME},
                "spec": {"selector": {"matchLabels": labels},
                         "updateStrategy": {"type": "RollingUpdate", "rollingUpdate": {"maxUnavailable": 1}},
                         "template": {"metadata": {"labels": labels}, "spec": {
                             "automountServiceAccountToken": False,
                             "terminationGracePeriodSeconds": 1,
                             "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                 "seccompProfile": {"type": "RuntimeDefault"}},
                             "containers": [{"name": "release", "image": IMAGE, "env": [{"name": ENV, "value": OLD}],
                                             "command": ["python", "-u", "-c",
                                                         "import os,time; print(os.environ['FIXTURE_RELEASE']); time.sleep(240)"],
                                             "readinessProbe": {"exec": {"command": ["python", "-c",
                                                 "import os,sys; sys.exit(os.environ['FIXTURE_RELEASE'] == 'fixture-rejected-candidate')"]},
                                                                "periodSeconds": 1, "timeoutSeconds": 2},
                                             "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                                                           "limits": {"cpu": "100m", "memory": "40Mi"}},
                                             "securityContext": {"readOnlyRootFilesystem": True,
                                                                 "allowPrivilegeEscalation": False,
                                                                 "capabilities": {"drop": ["ALL"]}}}]}}}})


def observe_release(lab, release, *, ready):
    deadline = time.monotonic() + 65
    while time.monotonic() < deadline:
        items = json.loads(lab.kubectl("get", "pods", "-l", f"app={NAME}", "-o", "json").stdout)["items"]
        active = [pod for pod in items if not pod["metadata"].get("deletionTimestamp")]
        for item in active:
            spec = item["spec"]
            observed_release = spec["containers"][0]["env"][0]["value"]
            conditions = {row["type"]: row["status"] for row in item.get("status", {}).get("conditions", [])}
            if observed_release != release or conditions.get("Ready") != ("True" if ready else "False"):
                continue
            name = item["metadata"]["name"]
            log = lab.kubectl("logs", name, allow_failure=True)
            if log.returncode == 0 and log.stdout.splitlines() == [release]:
                return {"release": release, "running_process_logged_release": True, "ready": ready}
        time.sleep(0.5)
    lab.block("The DaemonSet did not reach the expected observed release and readiness")


def rollout(lab, release):
    lab.kubectl("set", "env", f"daemonset/{NAME}", f"{ENV}={release}")


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    install(lab)
    before = observe_release(lab, OLD, ready=True)
    lab.check("red", "The running DaemonSet reports the older modeled release even though policy requires an approved release",
              before["release"] != APPROVED, before)

    rollout(lab, APPROVED)
    lab.kubectl("rollout", "status", f"daemonset/{NAME}", "--timeout=65s", timeout=75)
    updated = observe_release(lab, APPROVED, ready=True)
    lab.check("green", "The updated DaemonSet reports the approved live release and reaches readiness",
              updated["release"] == APPROVED and updated["ready"], updated)

    rollout(lab, REJECTED)
    candidate = observe_release(lab, REJECTED, ready=False)
    lab.kubectl("rollout", "undo", f"daemonset/{NAME}")
    lab.kubectl("rollout", "status", f"daemonset/{NAME}", "--timeout=65s", timeout=75)
    restored = observe_release(lab, APPROVED, ready=True)
    lab.check("positive", "An explicitly unready candidate is detected and rollback restores the approved live release",
              not candidate["ready"] and restored == updated,
              {"candidate_remained_unready": not candidate["ready"], "approved_release_restored": restored == updated})
    (lab.evidence / "driver-rollout-observations.json").write_text(json.dumps({
        "before": before, "updated": updated, "unready_candidate": candidate, "after_rollback": restored,
        "driver_is_modeled": True}, indent=2) + "\n")
