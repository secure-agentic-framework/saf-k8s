"""Run two bounded advisory-prioritization policies in real Kubernetes Jobs."""
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
CONFIG = "saf-cve-triage-fixture"
SCOPE = (
    "Kubernetes runs two Jobs over identical inert advisory metadata and synthetic inventory. "
    "The fixture compares the scheduling and triage outputs of severity-only and contextual rules. "
    "Live feeds, production inventory and patch SLA enforcement require separate evidence."
)


def evaluate(lab, mode):
    name = "saf-triage-" + mode
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 100,
                 "template": {"spec": {
                     "restartPolicy": "Never", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "triage", "image": IMAGE,
                                     "command": ["python", "/fixture/triage.py", mode],
                                     "securityContext": {"readOnlyRootFilesystem": True,
                                                         "allowPrivilegeEscalation": False,
                                                         "capabilities": {"drop": ["ALL"]}},
                                     "volumeMounts": [{"name": "fixture", "mountPath": "/fixture",
                                                       "readOnly": True}]}],
                     "volumes": [{"name": "fixture", "configMap": {"name": CONFIG}}],
                 }}},
    })
    lab.kubectl("wait", "--for=condition=Complete", f"job/{name}", "--timeout=105s", timeout=115)
    return json.loads(lab.kubectl("logs", f"job/{name}").stdout)


def run(lab):
    fixture = (HERE / "fixtures.json").read_text()
    expected = json.loads(fixture)["expected"]
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CONFIG},
        "data": {"fixtures.json": fixture, "triage.py": (HERE / "triage.py").read_text()},
    })
    severity = evaluate(lab, "severity-only")
    context = evaluate(lab, "context-aware")
    first = context[0]
    severity_ids = [row["id"] for row in severity]
    context_ids = [row["id"] for row in context]
    same = sorted(severity_ids) == sorted(context_ids) and len(severity_ids) == 2
    lab.check("red", "A completed severity-only Job ranks a different affected record first",
              same and severity_ids[0] != expected["high_risk_id"],
              {"identical_candidates": same, "severity_order": severity_ids})
    expected_range = {"versionStartIncluding": "1.34.0", "versionEndExcluding": "1.35.3"}
    ranked = (first["id"] == expected["high_risk_id"] and first["priority"] == "P1"
              and first["known_exploited"] and first["internet_exposed"]
              and first["affected_range"] == expected_range)
    lab.check("green", "The completed contextual Job ranks the exposed KEV fixture first",
              ranked, {"contextual_order": context_ids, "range": first["affected_range"],
                       "known_exploited": first["known_exploited"], "internet_exposed": first["internet_exposed"]})
    excluded = all(row["component"] != expected["nonaffected_component"] for row in context)
    lab.check("positive", "The version at the exclusive upper bound is absent from the findings",
              excluded, {"upper_boundary_excluded": excluded})
