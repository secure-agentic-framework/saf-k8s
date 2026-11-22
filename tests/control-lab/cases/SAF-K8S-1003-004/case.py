"""Validate a defensive ATT&CK Containers coverage register in native Jobs."""
import json
from pathlib import Path
import time

from fixtures import container

HERE = Path(__file__).resolve().parent
CONFIG = "saf-attack-coverage"
AS_OF = "2026-11-22"
PYTHON = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
SCOPE = (
    "Disposable Kind v1.36.1 Jobs validate three selected Containers technique records "
    "against pinned MITRE v20.1 metadata and case-owned synthetic event and mitigation "
    "artifacts. The validator checks accountable gaps and rejects unsupported deployment "
    "claims. Full-matrix assessment and operational coverage require separate evidence."
)


def run_job(lab, name, register, enforce=True):
    command = (["python", "/fixture/validate.py", f"/fixture/{register}.json", AS_OF] if enforce else
               ["python", "-c", "import json,sys; json.load(open(sys.argv[1])); print('{\"status\":\"accepted-before-gate\",\"errors\":[]}')", f"/fixture/{register}.json"])
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 65,
          "template": {"metadata": {"labels": {"saf.review": name}}, "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "containers": [container("review", image=PYTHON, command=command,
              volumeMounts=[{"name": "fixture", "mountPath": "/fixture", "readOnly": True}])],
            "volumes": [{"name": "fixture", "configMap": {"name": CONFIG}}]}}}})
    deadline = time.monotonic() + 70
    while time.monotonic() < deadline:
        state = json.loads(lab.kubectl("get", "job", name, "-o", "json", timeout=15).stdout)
        settled = [c for c in state.get("status", {}).get("conditions", [])
                   if c.get("status") == "True" and c.get("type") in {"Failed", "Complete"}]
        if settled:
            break
        time.sleep(1)
    else:
        lab.block(f"Review Job {name} did not reach a terminal condition")
    podlist = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={name}", "-o", "json", timeout=15).stdout)
    pod, = podlist["items"]
    terminated = pod["status"]["containerStatuses"][0]["state"]["terminated"]
    logs = lab.kubectl("logs", f"job/{name}", timeout=15).stdout
    if not logs.strip():
        lab.block(f"Review Job {name} returned no decision")
    return {"job": name, "job_uid": state["metadata"]["uid"], "pod_uid": pod["metadata"]["uid"],
            "controller": settled[0]["type"], "exit_code": terminated["exitCode"], "review": json.loads(logs)}


def run(lab):
    data = {file.name: file.read_text() for file in sorted((HERE / "fixtures").iterdir()) if file.is_file()}
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CONFIG}, "data": data})
    baseline = run_job(lab, "mapping-without-gate", "invalid-mapping", False)
    invalid = run_job(lab, "mapping-invalid", "invalid-mapping")
    valid = run_job(lab, "mapping-current", "mapping")
    raw = {"baseline": baseline, "invalid": invalid, "valid": valid,
           "source": json.loads(data["attack-metadata.json"])}
    (lab.evidence / "mapping-review-report.json").write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    lab.check("red", "The ungated Job accepts the same invalid defensive coverage register",
              baseline["controller"] == "Complete" and baseline["exit_code"] == 0
              and baseline["review"]["status"] == "accepted-before-gate",
              {"ungated_job_completed": baseline["controller"] == "Complete"})
    errors = [
        "deployment-claim-lacks-independent-evidence:T1610", "event-reference-mismatch:T1611",
        "gap-disposition-missing:T1613", "official-technique-or-tactic-mismatch:T1610",
    ]
    lab.check("green", "Native validation rejects the wrong tactic, event, gap owner and unsupported deployment claim",
              invalid["controller"] == "Failed" and invalid["exit_code"] == 1
              and invalid["review"]["errors"] == sorted(errors),
              {"errors": invalid["review"]["errors"]})
    rows = valid["review"]["results"]
    lab.check("positive", "The corrected register passes with three accountable gaps and unknown deployment coverage",
              valid["controller"] == "Complete" and valid["exit_code"] == 0
              and valid["review"]["status"] == "pass" and not valid["review"]["errors"]
              and len(rows) == 3 and all(row["owner"] and row["gap"] == "open" and row["deployment"] == "unknown"
                                         for row in rows),
              {"techniques": [row["technique"] for row in rows], "owned_gaps": len(rows),
               "deployment_states": sorted({row["deployment"] for row in rows})})
