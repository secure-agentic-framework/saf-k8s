"""Review synthetic SAF-to-framework mapping metadata in an isolated Kind cluster."""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
NODE_IMAGE = ("kindest/node:v1.36.1@sha256:"
              "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5")
REVIEW_IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
                "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
SCOPE = (
    "Disposable Kind Kubernetes v1.36.1 cluster. A tokenless, non-root Job reads only synthetic mapping metadata "
    "and runs a deterministic metadata reviewer. It compares a deliberately flawed draft with a reviewed fixture, "
    "using fictional, preapproved applicability inputs. It checks framework identifier/authority labels, evidence "
    "references, explicit gaps, safeguards and named fixture source edition/revision metadata. This is not a legal applicability assessment, control-effectiveness "
    "test, attestation, or compliance conclusion."
)


def kubectl(lab, *args, **kwargs):
    return lab.kubectl(*args, **kwargs)


def json_result(result, what):
    try:
        return json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        raise RuntimeError(f"Could not parse {what} JSON evidence")


def run_review(lab, mode):
    name = f"mapping-review-{mode}"
    job = {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "labels": {"case": "saf-k8s-1006-001", "mode": mode}},
        "spec": {
            "backoffLimit": 0, "activeDeadlineSeconds": 60, "ttlSecondsAfterFinished": 300,
            "template": {
                "metadata": {"labels": {"case": "saf-k8s-1006-001", "mode": mode}},
                "spec": {
                    "restartPolicy": "Never", "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                        "runAsGroup": 10001, "seccompProfile": {"type": "RuntimeDefault"}},
                    "volumes": [{"name": "inputs", "configMap": {"name": "mapping-inputs"}},
                                {"name": "reviewer", "configMap": {"name": "reviewer-code"}}],
                    "containers": [{
                        "name": "reviewer", "image": REVIEW_IMAGE, "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "-B", "/review/review.py", "/inputs/fixtures.json", mode],
                        "securityContext": {"allowPrivilegeEscalation": False,
                                             "readOnlyRootFilesystem": True,
                                             "capabilities": {"drop": ["ALL"]}},
                        "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                      "limits": {"cpu": "250m", "memory": "96Mi"}},
                        "volumeMounts": [{"name": "inputs", "mountPath": "/inputs", "readOnly": True},
                                         {"name": "reviewer", "mountPath": "/review", "readOnly": True}],
                    }],
                },
            },
        },
    }
    kubectl(lab, "create", "-f", "-", payload=json.dumps(job))
    kubectl(lab, "wait", f"job/{name}", "--for=condition=complete", "--timeout=90s", timeout=95)
    pods = json_result(kubectl(lab, "get", "pods", "-l", f"job-name={name}", "-o", "json"), f"{name} pods")["items"]
    if len(pods) != 1:
        lab.block(f"Expected one tokenless reviewer Pod for {name}")
    pod = pods[0]
    if pod["spec"].get("automountServiceAccountToken") is not False:
        lab.block(f"Reviewer Pod {name} unexpectedly has service-account token automount enabled")
    logs = kubectl(lab, "logs", f"pod/{pod['metadata']['name']}").stdout
    try:
        report = json.loads(logs)
    except json.JSONDecodeError:
        lab.block(f"Reviewer Pod {name} emitted invalid JSON")
    if report.get("mode") != mode or report.get("review_type") != "metadata-only":
        lab.block(f"Reviewer Pod {name} did not emit the expected mode-tagged metadata report")
    (lab.evidence / f"{mode}-review.json").write_text(json.dumps(report, indent=2) + "\n")
    (lab.evidence / f"{mode}-pod.json").write_text(json.dumps(pod, indent=2) + "\n")
    return report, pod


def run(lab):
    fixture = json.loads((HERE / "fixtures.json").read_text())
    for name, key, value in (
        ("mapping-inputs", "fixtures.json", json.dumps(fixture)),
        ("reviewer-code", "review.py", (HERE / "review.py").read_text()),
    ):
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                    "immutable": True, "data": {key: value}})

    draft, _ = run_review(lab, "draft")
    misattributed = [item for item in draft["findings"] if item["type"] == "misattributed-authority"]
    draft_missing = [item for item in draft["findings"] if item["type"] == "missing-evidence"]
    bad_scope = any(item["type"] == "unapproved-applicability-input" for item in draft["findings"])
    lab.check("red", "Draft records expose wrong authority labels, missing evidence, and unapproved applicability",
              not draft["review_integrity_pass"] and {item["requirement_id"] for item in misattributed} == {
                  "EU-AI-ACT-Article-12", "NIST-AI-RMF-GOVERN-1.1", "AICPA-TSC-2017-CC6.1"}
              and len(draft_missing) == 3 and bad_scope,
              {"review_integrity_pass": draft["review_integrity_pass"],
               "misattributed_authority_count": len(misattributed),
               "missing_evidence_count": len(draft_missing),
               "unapproved_applicability_detected": bad_scope})

    overclaimed, _ = run_review(lab, "overclaimed")
    first = "EU-AI-ACT-Article-12"
    comparator = sorted(item["type"] for item in overclaimed["findings"]
                        if item["requirement_id"] == first)
    lab.check("red", "Authority-scoped applicability, unresolved evidence and premature closure are rejected",
              not overclaimed["review_integrity_pass"] and comparator == [
                  "unapproved-applicability-input", "unresolved-evidence-reference",
                  "unsupported-coverage-closure"], {"reasons": comparator})

    reviewed, _ = run_review(lab, "reviewed")
    findings = reviewed["findings"]
    integrity = reviewed["review_integrity_pass"] and not any(
        item["type"] in {"misattributed-authority", "unknown-framework-identifier", "missing-metadata",
                         "unresolved-evidence-reference", "undocumented-open-gap",
                         "unapproved-applicability-input", "missing-mapping-row"}
        for item in findings)
    lab.check("green", "Reviewed mapping has valid identifiers, attributed authorities, approved scenario inputs, and complete review metadata",
              integrity and reviewed["legal_applicability_determined"] is False
              and reviewed["compliance_conclusion_made"] is False,
              {"review_integrity_pass": integrity,
               "authorities_correctly_attributed": not any(item["type"] == "misattributed-authority" for item in findings),
               "all_expected_identifiers_present": not any(item["type"] == "missing-mapping-row" for item in findings),
               "legal_applicability_determined": reviewed["legal_applicability_determined"],
               "compliance_conclusion_made": reviewed["compliance_conclusion_made"]})

    open_gaps = [item for item in findings if item["type"] == "open-gap-recorded"]
    missing_art15 = any(item["requirement_id"] == "EU-AI-ACT-Article-15"
                        and item.get("evidence_refs") == [] and item.get("compensating_safeguards")
                        for item in open_gaps)
    gaps_missing_evidence = {item["requirement_id"] for item in open_gaps
                   if item.get("evidence_refs") == [] and item.get("compensating_safeguards")}
    lab.check("positive", "The report preserves unproven coverage as open gaps and records interim safeguards",
              len(open_gaps) == 9 and missing_art15
              and {"AICPA-TSC-2017-CC6.1", "AICPA-TSC-2017-CC7.2"}.issubset(gaps_missing_evidence)
              and reviewed["framework_coverage_complete"] is False,
              {"open_gap_count": len(open_gaps), "article_15_missing_evidence_surfaced": missing_art15,
               "gap_ids_missing_evidence": sorted(gaps_missing_evidence),
               "safeguards_present_for_open_gaps": all(item.get("compensating_safeguards") for item in open_gaps),
               "framework_coverage_complete": reviewed["framework_coverage_complete"]})

    # Preserve non-secret, raw API observations alongside the Job stdout reports.
    raw = json_result(kubectl(lab, "get", "configmaps", "mapping-inputs", "reviewer-code", "-o", "json"),
                      "synthetic ConfigMap")
    (lab.evidence / "input-configmaps.json").write_text(json.dumps(raw, indent=2) + "\n")

    # Reuse the exact case's tokenless, non-root reviewer Job and ConfigMaps.
    report, _ = run_review(lab, "source-review")
    matrix = report.get("matrix", {})
    counterfactuals = report.get("counterfactuals", {})
    matched = (
        report.get("review_integrity_pass") is True
        and len(matrix) == 6
        and set(matrix.values()) == {"current"}
        and counterfactuals == {
            "wrong_edition": "conflict",
            "source_change_requires_review": "review-required",
            "missing_source_identity": "unknown",
        }
        and report.get("legal_applicability_determined") is False
        and report.get("compliance_conclusion_made") is False
    )
    lab.check("positive", "Versioned framework source identities are bound and source changes require renewed review",
              matched,
              {"six_fixture_sources_current": report.get("review_integrity_pass") is True
               and len(matrix) == 6 and set(matrix.values()) == {"current"},
               "wrong_edition_rejected": counterfactuals.get("wrong_edition") == "conflict",
               "source_change_requires_review": counterfactuals.get("source_change_requires_review") == "review-required",
               "missing_source_identity_unknown": counterfactuals.get("missing_source_identity") == "unknown",
               "legal_applicability_determined": report.get("legal_applicability_determined"),
               "compliance_conclusion_made": report.get("compliance_conclusion_made")})
    (lab.evidence / "source-review.raw.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
