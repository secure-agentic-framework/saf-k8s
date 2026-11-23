"""SAF-K8S-0905-028: offline, metadata-only dependency gate exercise."""
import json
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
PYTHON = ("docker.io/library/python:3.13.2-alpine@sha256:"
          "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352")
ADVISORY = "SAF-FAB-2026-0905-028-001"
DIRECT = "saf-ml-fixture"
TRANSITIVE = "saf-fixture-core"
VULNERABLE_VERSION = "0.4.0"
PATCHED_VERSION = "0.4.1"

SCOPE = (
    "One disposable Kubernetes cluster job builds tiny metadata-only wheels for two fictitious "
    "packages, installs them with pip --no-index from local wheelhouse directories, and inspects "
    "installed metadata. The red observation records the same flagged installation as promotable "
    "under an explicitly inactive gate; green blocks it; positive installs a fresh patched fixture "
    "and confirms its direct-to-transitive dependency path. No real third-party package, CVE, "
    "package code, vulnerability behavior, or production promotion system is involved."
)


def _job(lab):
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "dependency-gate-worker"}, "immutable": True,
        "data": {"worker.py": (HERE / "worker.py").read_text()},
    })
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": "dependency-gate"},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 120,
                 "template": {"metadata": {"labels": {"app": "dependency-gate"}}, "spec": {
                     "restartPolicy": "Never", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "worker", "image": PYTHON,
                                     "imagePullPolicy": "IfNotPresent",
                                     "command": ["python", "-B", "/worker/worker.py"],
                                     "resources": {"requests": {"cpu": "10m", "memory": "48Mi"},
                                                   "limits": {"cpu": "200m", "memory": "128Mi"}},
                                     "securityContext": {"allowPrivilegeEscalation": False,
                                                         "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}},
                                     "volumeMounts": [
                                         {"name": "worker", "mountPath": "/worker", "readOnly": True},
                                         {"name": "scratch", "mountPath": "/tmp"}]}],
                     "volumes": [
                         {"name": "worker", "configMap": {"name": "dependency-gate-worker",
                                                               "defaultMode": 292}},
                         {"name": "scratch", "emptyDir": {"sizeLimit": "32Mi"}}]}}}})
    deadline = time.monotonic() + 135
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", "job", "dependency-gate", "-o", "json").stdout)
        states = {x["type"] for x in job.get("status", {}).get("conditions", [])
                  if x["status"] == "True"}
        if "Failed" in states:
            lab.kubectl("logs", "job/dependency-gate", allow_failure=True)
            lab.block("Dependency-gate fixture job failed")
        if "Complete" in states:
            return lab.kubectl("logs", "job/dependency-gate").stdout
        time.sleep(0.5)
    lab.block("Dependency-gate fixture job timed out")


def check_observations(lab, observations):
    original = {DIRECT: {"version": "1.0.0", "requires": [f"{TRANSITIVE}>=0.4,<1"]},
                TRANSITIVE: {"version": VULNERABLE_VERSION, "requires": []}}
    patched = {**original, TRANSITIVE: {"version": PATCHED_VERSION, "requires": []}}
    finding = {"id": ADVISORY, "package": TRANSITIVE, "version": VULNERABLE_VERSION}

    disabled = observations["disabled"]
    lab.check("red", "The inactive gate writes a promotion record for the pinned dependency with a fixture advisory",
              disabled == {"installed": original, "matches": [finding], "enforced": False,
                           "decision": "accepted", "promoted_record": {"installed": original}},
              disabled)
    blocked = observations["blocked"]
    lab.check("green", "The active gate withholds promotion of the same installed dependency and records the exact match",
              blocked == {"installed": original, "matches": [finding], "enforced": True,
                          "decision": "blocked", "promoted_record": None},
              blocked)
    accepted = observations["patched"]
    lab.check("positive", "A fresh installation replaces the flagged transitive dependency and produces a promotion record",
              accepted == {"installed": patched, "matches": [], "enforced": True,
                           "decision": "accepted", "promoted_record": {"installed": patched}},
              accepted)


def run(lab):
    try:
        observations = json.loads(_job(lab))
    except json.JSONDecodeError as error:
        lab.block(f"Dependency gate worker returned invalid evidence: {error}")
    (lab.evidence / "dependency-gate.json").write_text(json.dumps(observations, indent=2, sort_keys=True) + "\n")
    check_observations(lab, observations)
