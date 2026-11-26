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
    "of mislabeled inert bytes before value access. A standard JSON parser separately consumes "
    "only an exact allowlisted declarative input. This does not test a production model loader, "
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

    ordinary = observations["declarative_json"]
    good = ordinary["approved"]
    approved_digest = "50e0d5c3ffb448eb7435ed99a8cb6118438fc2765248b459d313e493ed5a5473"
    unapproved_digest = "d7f330b264a1c639e2b008011b7956c737b9b3271ecee68f48d73336760e5a53"
    lab.check("positive", "Exact allowlisted JSON data digest is admitted and parsed by the standard declarative loader",
              good == {"declared_format": "json-data", "sha256": approved_digest,
                       "admitted": True, "loader_sha256": approved_digest,
                       "status": "JSON_DATA_LOADED", "values": [1.25, -2.5],
                       "counters": {"deny_count": 0, "loader_calls": 1, "values_read": 2}},
              good)
    wrong_format = ordinary["wrong_format"]
    lab.check("green", "A wrong format label is denied before the JSON data loader",
              wrong_format["sha256"] == approved_digest and wrong_format["declared_format"] == "legacy-inert"
              and wrong_format["admitted"] is False and wrong_format["loader_sha256"] is None
              and wrong_format["status"] == "DENY_BEFORE_LOADER"
              and wrong_format["counters"] == {"deny_count": 1, "loader_calls": 0, "values_read": 0},
              wrong_format)
    wrong_digest = ordinary["unapproved_digest"]
    lab.check("green", "An unapproved JSON digest is denied before the JSON data loader",
              wrong_digest["sha256"] == unapproved_digest and wrong_digest["declared_format"] == "json-data"
              and wrong_digest["admitted"] is False and wrong_digest["loader_sha256"] is None
              and wrong_digest["status"] == "DENY_BEFORE_LOADER"
              and wrong_digest["counters"] == {"deny_count": 1, "loader_calls": 0, "values_read": 0},
              wrong_digest)

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
