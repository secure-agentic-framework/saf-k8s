"""Exercise OCTAVE risk-traceability review as native Kubernetes Jobs."""
import json
from pathlib import Path
import time

from fixtures import container

HERE = Path(__file__).resolve().parent
CONFIG = "octave-fixtures"
AS_OF = "2026-11-22"
PYTHON = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
SCOPE = (
    "Kubernetes v1.36.1 Kind runs independent native review Jobs over synthetic OCTAVE worksheets. "
    "The gate checks Phase 1 asset/impact/threat profiles, Phase 2 supporting infrastructure and "
    "vulnerability evidence, and Phase 3 tolerance-linked treatment and review cadence. It proves "
    "record completeness and stable decisions only; organizational risk scoring, stakeholder "
    "judgment, evidence truth, implementation, and actual risk reduction require separate evidence."
)


def run_job(lab, items, name, worksheet, enforce=True):
    command = (["python", "/fixture/review_gate.py", f"/fixture/{worksheet}.json", "--as-of", AS_OF] if enforce else
               ["python", "-c", "import json,sys; json.load(open(sys.argv[1])); print('{\"status\":\"accepted-before-gate\",\"errors\":[]}')", f"/fixture/{worksheet}.json"])
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 65,
          "template": {"metadata": {"labels": {"saf.review": name}}, "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "containers": [container("review", image=PYTHON, command=command,
              volumeMounts=[{"name": "fixture", "mountPath": "/fixture", "readOnly": True}])],
            "volumes": [{"name": "fixture", "configMap": {"name": CONFIG, "items": items}}]}}}})
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
    names = ("incomplete", "complete")
    data = {"review_gate.py": (HERE / "review_gate.py").read_text()}
    data.update({f"{n}.json": (HERE / "fixtures" / f"{n}.json").read_text() for n in names})
    evidence = HERE / "fixtures" / "evidence"
    data.update({source.name: source.read_text() for source in sorted(evidence.glob("*.md"))})
    items = [{"key": key, "path": f"evidence/{key}" if key.endswith(".md") else key} for key in data]
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CONFIG}, "data": data})
    disabled = run_job(lab, items, "octave-no-gate", "incomplete", False)
    missing = run_job(lab, items, "octave-incomplete", "incomplete")
    complete = run_job(lab, items, "octave-complete", "complete")
    raw = {"as_of": AS_OF, "disabled": disabled, "incomplete": missing, "complete": complete}
    (lab.evidence / "octave-job-observations.json").write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    lab.check("red", "Disabled review accepts a structurally readable incomplete worksheet",
        (disabled["controller"], disabled["exit_code"], disabled["review"]["status"]) == ("Complete", 0, "accepted-before-gate"),
        {"controller": disabled["controller"], "exit_code": disabled["exit_code"]})
    errors = missing["review"].get("errors", [])
    lab.check("green", "Native Job rejects gaps in impact-to-treatment traceability and review cadence",
        missing["controller"] == "Failed" and missing["exit_code"] == 1 and
        "phase1-impact-missing:model-core" in errors and "phase2-infrastructure-link-missing:model-core" in errors and
        "phase3-tolerance-missing:model-core" in errors and "phase3-treatment-missing:model-core" in errors and
        "review-cadence-missing" in errors, {"errors": errors})
    lab.check("positive", "Complete synthetic OCTAVE worksheet passes with deterministic decision and independent evidence fields",
        complete["controller"] == "Complete" and complete["exit_code"] == 0 and complete["review"] == {"status": "pass", "errors": []},
        {"status": complete["review"]["status"], "assets": 4})
