"""Exercise the STRIDE review gate as Kubernetes Jobs."""
import json
from pathlib import Path
import time

from fixtures import container

HERE = Path(__file__).resolve().parent
SCOPE = (
    "Kubernetes v1.36.1 Kind executes independent architecture-review Jobs against synthetic "
    "records. An unenforced path accepts an incomplete record. The enabled gate rejects incomplete "
    "and stale records and accepts an internally consistent record covering nine component classes. "
    "Independent case-owned approval labels and evidence links model the review workflow. "
    "Actual threat judgment, reviewer authority and deployment coverage need separate evidence."
)
AS_OF = "2026-11-22"
CONFIG = "saf-stride-fixtures"
PYTHON = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"


def run_review(lab, items, name, record, enforce):
    basename = record + ".json"
    program = (
        ["python", "/fixture/review_gate.py", f"/fixture/{basename}", "--today", AS_OF]
        if enforce else ["python", "-c",
                         'import json,sys; json.load(open(sys.argv[1])); print(json.dumps({"status":"accepted-before-gate","errors":[]}))',
                         f"/fixture/{basename}"]
    )
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 65,
                 "template": {"metadata": {"labels": {"saf.review": name}},
                              "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                                       "containers": [container(
                                           "review", image=PYTHON, command=program,
                                           volumeMounts=[{"name": "review", "mountPath": "/fixture", "readOnly": True}])],
                                       "volumes": [{"name": "review", "configMap": {"name": CONFIG, "items": items}}]}}},
    })
    deadline = time.monotonic() + 70
    while time.monotonic() < deadline:
        state = json.loads(lab.kubectl("get", "job", name, "-o", "json", timeout=15).stdout)
        settled = [condition for condition in state.get("status", {}).get("conditions", [])
                   if condition["status"] == "True" and condition["type"] in {"Failed", "Complete"}]
        if settled:
            break
        time.sleep(1)
    else:
        lab.block(f"Review Job {name} did not reach a terminal condition")
    work = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={name}", "-o", "json", timeout=15).stdout)
    pod, = work["items"]
    outcome = pod["status"]["containerStatuses"][0]["state"]["terminated"]
    logs = lab.kubectl("logs", f"job/{name}", timeout=15).stdout
    if not logs.strip():
        lab.block(f"Review Job {name} exited with {outcome['exitCode']} without a gate decision")
    signals = json.loads(logs)
    return {"job": name, "job_uid": state["metadata"]["uid"], "pod_uid": pod["metadata"]["uid"],
            "controller": settled[0]["type"], "exit_code": outcome["exitCode"], "review": signals}


def run(lab):
    files = {"review_gate.py": (HERE / "review_gate.py").read_text()}
    fixtures = HERE / "fixtures"
    names = ("incomplete", "stale", "reviewed-valid")
    files.update({f"{name}.json": (fixtures / f"{name}.json").read_text() for name in names})
    files.update({file.name: file.read_text() for file in (fixtures / "evidence").glob("*.md")})
    items = [{"key": name, "path": "evidence/" + name if name.endswith(".md") else name} for name in files]
    obj = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CONFIG}, "data": files}
    lab.create(obj)
    original = run_review(lab, items, "stride-baseline", "incomplete", False)
    incomplete = run_review(lab, items, "stride-incomplete", "incomplete", True)
    stale = run_review(lab, items, "stride-stale", "stale", True)
    valid = run_review(lab, items, "stride-current", "reviewed-valid", True)
    raw = {"as_of": AS_OF, "baseline": original, "incomplete": incomplete, "stale": stale, "valid": valid}
    (lab.evidence / "stride-gate-observations.json").write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    lab.check("red", "The workflow without review enforcement accepts the same incomplete submission",
              (original["controller"], original["exit_code"], original["review"]["status"]) ==
              ("Complete", 0, "accepted-before-gate"), {"completed_without_gate": True})
    observed = incomplete["review"]["errors"]
    lab.check("green", "Native Job rejects the same submission for missing component coverage and evidence",
              incomplete["controller"] == "Failed" and incomplete["exit_code"] == 1
              and "coverage-missing:api-server:spoofing" in observed
              and "data-flow-link-invalid:api-server:evidence/missing-fixture.md" in observed,
              {"coverage_and_evidence_errors": observed})
    lab.check("green", "Native Job rejects an otherwise complete review after its due date",
              stale["controller"] == "Failed" and stale["exit_code"] == 1
              and stale["review"]["errors"] == ["review-stale-or-missing"], {"freshness_enforced": True})
    approval = json.loads(files["reviewed-valid.json"])
    lab.check("positive", "The independent complete review produces a successful native Job and clean decision",
              valid["controller"] == "Complete" and valid["exit_code"] == 0
              and valid["review"] == {"status": "pass", "errors": []},
              {"components": len(approval["components"]), "mapped_threats": len(approval["threats"]),
               "named_approval_roles": len(approval["review"]["approvals"])})
