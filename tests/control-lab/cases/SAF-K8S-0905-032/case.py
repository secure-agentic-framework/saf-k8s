"""SAF-K8S-0905-032: inert model-format allowlist lab case."""
import json
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
PYTHON = ("docker.io/library/python:3.13.2-alpine@sha256:"
          "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352")

SCOPE = (
    "Runs one fixture-owned Kubernetes Job in the precreated saf-test namespace. "
    "All inputs are constants: fixed inert legacy bytes and a tiny F32[2] SafeTensors-shaped "
    "payload. Red records a permissive decision reaching only a counted stub; green denies the "
    "same bytes before loader invocation; positive checks approved-format values and rejection "
    "of mislabeled inert bytes before value access. This does not test a production model loader, "
    "PyTorch, hostile payload behavior, general SafeTensors compatibility, or 0905-033 structure/metadata checks."
)


def _job(lab):
    name = "model-format-policy"
    worker = {"apiVersion": "v1", "kind": "ConfigMap",
              "metadata": {"name": "model-format-worker"},
              "immutable": True, "data": {"worker.py": (HERE / "worker.py").read_text()}}
    lab.create(worker)
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 60,
                 "template": {"metadata": {"labels": {"app": name}}, "spec": {
                     "restartPolicy": "Never", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "fixture", "image": PYTHON,
                                     "imagePullPolicy": "IfNotPresent",
                                     "command": ["python", "-B", "/worker/worker.py"],
                                     "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                                   "limits": {"cpu": "100m", "memory": "64Mi"}},
                                     "securityContext": {"allowPrivilegeEscalation": False,
                                                         "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}},
                                     "volumeMounts": [{"name": "worker", "mountPath": "/worker",
                                                       "readOnly": True}]}],
                     "volumes": [{"name": "worker", "configMap": {
                         "name": "model-format-worker", "defaultMode": 292}}]}}}})
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)
        states = {condition["type"] for condition in job.get("status", {}).get("conditions", [])
                  if condition.get("status") == "True"}
        if "Failed" in states:
            lab.kubectl("logs", "job/" + name, allow_failure=True)
            lab.block("Fixture Job failed: " + name)
        if "Complete" in states:
            log = lab.kubectl("logs", "job/" + name).stdout
            try:
                return json.loads(log)
            except json.JSONDecodeError:
                lab.block("Fixture Job did not emit its stable JSON result: " + name)
        time.sleep(0.5)
    lab.block("Fixture Job timed out: " + name)


def check_observations(lab, observations):
    permissive = observations["permissive"]
    legacy = {"declared_format": "legacy-inert", "sha256": permissive["sha256"]}
    counters = {"deny_count": 0, "loader_calls": 0, "stub_calls": 0, "values_read": 0}
    lab.check("red", "The permissive policy routes the fixed inert representation to a counted stub",
              permissive == {**legacy, "status": "STUB_ONLY", "counters": {**counters, "stub_calls": 1}},
              permissive)

    restricted = observations["restricted"]
    lab.check("green", "The allowlist denies the same input before invoking any loader",
              restricted == {**legacy, "status": "DENY_FORMAT", "counters": {**counters, "deny_count": 1}},
              restricted)

    approved = observations["approved"]
    lab.check("positive", "The same allowlist routes approved bytes to the loader and returns the exact fixture values",
              approved["declared_format"] == "safetensors" and approved["status"] == "SAFE_LOADED"
              and approved["sha256"] != legacy["sha256"] and approved["values"] == [1.25, -2.5]
              and approved["counters"] == {**counters, "loader_calls": 1, "values_read": 2},
              approved)

    mislabeled = observations["mislabeled"]
    lab.check("green", "Mislabeling the same inert bytes does not cause the approved parser to consume model values",
              mislabeled == {"declared_format": "safetensors", "sha256": legacy["sha256"],
                             "status": "REJECTED_BEFORE_VALUES",
                             "counters": {**counters, "loader_calls": 1}},
              mislabeled)


def run(lab):
    observations = _job(lab)
    (lab.evidence / "model-format-allowlist.json").write_text(
        json.dumps(observations, indent=2, sort_keys=True) + "\n")
    check_observations(lab, observations)
