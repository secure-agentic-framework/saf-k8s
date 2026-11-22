"""Consume versioned synthetic governance ConfigMaps from normal kind Jobs."""
import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
SCOPE = (
    "A disposable Kubernetes v1.36.1 cluster stores and validates synthetic taxonomy versions. "
    "Real Jobs distinguish missing handling rules and ambiguous terms from structurally valid "
    "documents, while old and newer revisions stay independently selectable. Production adoption, "
    "the authority of owners and reviewers, and change cadence require separate evidence."
)


def register(lab, name, fixture):
    text = (HERE / fixture).read_text()
    version = json.loads(text)["taxonomyVersion"]
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": name, "labels": {"saf-k8s.example/taxonomy-version": version}},
        "immutable": True, "data": {"taxonomy.json": text},
    })


def assess(lab, name):
    job = {
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
        "spec": {"activeDeadlineSeconds": 60, "backoffLimit": 0, "template": {"spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "validate", "image": IMAGE,
                "command": ["python", "/app/validator.py"],
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [{"name": "taxonomy", "mountPath": "/taxonomy", "readOnly": True},
                                 {"name": "app", "mountPath": "/app", "readOnly": True}],
            }],
            "volumes": [{"name": "taxonomy", "configMap": {"name": name}},
                        {"name": "app", "configMap": {"name": "taxonomy-validator"}}],
        }}},
    }
    lab.create(job)
    deadline = time.monotonic() + 85
    while time.monotonic() < deadline:
        status = json.loads(lab.kubectl("get", f"job/{name}", "-o", "json").stdout).get("status", {})
        terminal = {item["type"] for item in status.get("conditions", []) if item["status"] == "True"}
        if terminal & {"Complete", "Failed"}:
            output = lab.kubectl("logs", f"job/{name}").stdout
            return "Complete" in terminal, json.loads(output)
        time.sleep(1)
    lab.block("The in-cluster taxonomy Job did not reach a terminal condition")


def run(lab):
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "taxonomy-validator"},
        "data": {"validator.py": (HERE / "validator.py").read_text()},
    })
    invalid, current, updated = "taxonomy-ambiguous", "taxonomy-v1-0-0", "taxonomy-v1-1-0"
    register(lab, invalid, "taxonomy-v1.0.0-ambiguous.json")
    succeeded, diagnostics = assess(lab, invalid)
    findings = diagnostics["defects"]
    ambiguous = any("ambiguous classification term 'staff-only'" in item for item in findings)
    incomplete = "categories[2].handling is required" in findings
    lab.check("red", "The in-cluster taxonomy consumer rejects ambiguous terms and a missing handling rule",
              not succeeded and ambiguous and incomplete,
              {"stored_document": True, "ambiguous_term_rejected": ambiguous,
               "missing_handling_rejected": incomplete})

    register(lab, current, "taxonomy-v1.0.0.json")
    succeeded, initial = assess(lab, current)
    valid = succeeded and initial["taxonomy_version"] == "1.0.0" and not initial["defects"]
    lab.check("green", "The same consumer accepts a versioned taxonomy with complete categories",
              valid and initial["category_count"] == 3,
              {"valid_version": valid, "category_count": initial["category_count"]})

    register(lab, updated, "taxonomy-v1.1.0.json")
    succeeded, newer = assess(lab, updated)
    original = json.loads(lab.kubectl("get", f"configmap/{current}", "-o", "json").stdout)
    old = json.loads(original["data"]["taxonomy.json"])
    retained = original["immutable"] is True and old["taxonomyVersion"] == "1.0.0"
    reviewed = newer["governance"]["approvalRecord"] == "SYNTHETIC-RECORD-026-V2"
    newer_matches = succeeded and newer["taxonomy_version"] == "1.1.0" and not newer["defects"]
    lab.check("positive", "A consumer can select the newer revision while the older record remains available",
              retained and reviewed and newer_matches and newer["category_count"] == 4,
              {"retained_original": retained, "new_version_valid": newer_matches,
               "declared_fixture_approval": reviewed, "new_category_count": newer["category_count"]})
