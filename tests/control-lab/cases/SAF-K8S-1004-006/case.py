"""Compare single-signal and bounded cross-source triage on synthetic records."""
import json
from datetime import datetime
from pathlib import Path


HERE = Path(__file__).resolve().parent
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
CONFIG = "saf-1004-006-fixtures"
SCOPE = (
    "One disposable Kind v1.36.1 cluster. Two restricted, tokenless Jobs process only bundled, "
    "invented defensive metadata. Correlation requires exact cluster, namespace, workload and a five-minute "
    "event-time window; business context is validity-bounded and can change analyst review urgency. "
    "The fixture makes no attribution or employment decision. It does not collect live audit, physical, "
    "organizational, HR, or SIEM/SOAR data and does not establish deployed coverage or control operation."
)


def evaluate(lab, mode):
    name = "saf-1004-006-" + mode
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90,
                 "template": {"spec": {
                     "restartPolicy": "Never", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "triage", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                                     "command": ["python", "/fixture/triage.py", mode],
                                     "securityContext": {"readOnlyRootFilesystem": True,
                                                         "allowPrivilegeEscalation": False,
                                                         "capabilities": {"drop": ["ALL"]}},
                                     "volumeMounts": [{"name": "fixture", "mountPath": "/fixture",
                                                       "readOnly": True}]}],
                     "volumes": [{"name": "fixture", "configMap": {"name": CONFIG}}],
                 }}}
    })
    lab.kubectl("wait", "--for=condition=Complete", f"job/{name}", "--timeout=100s", timeout=110)
    return json.loads(lab.kubectl("logs", f"job/{name}").stdout)


def run(lab):
    fixture_text = (HERE / "fixtures.json").read_text()
    fixture = json.loads(fixture_text)
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CONFIG},
        "data": {"fixtures.json": fixture_text, "triage.py": (HERE / "triage.py").read_text()},
    })
    severity = evaluate(lab, "single-signal")
    contextual = evaluate(lab, "correlated")
    expected = fixture["expected"]
    severity_ids = [row["event_id"] for row in severity]
    contextual_ids = [row["event_id"] for row in contextual]
    by_id = {row["event_id"]: row for row in contextual}
    same_candidates = sorted(severity_ids) == sorted(contextual_ids) and len(contextual_ids) == len(fixture["technical_events"])

    lab.check("red", "Single-signal comparator ranks the higher-severity record first",
              same_candidates and severity_ids[:2] == [
                  expected["severity_only_first"], expected["severity_only_second"]],
              {"same_candidate_set": same_candidates, "single_signal_order": severity_ids,
               "first_urgency": severity[0]["review_urgency"]})

    exact = by_id[expected["exact_join_event"]]
    independent_priority = (
        same_candidates and severity_ids[0] == expected["severity_only_first"]
        and contextual_ids[:2] == [expected["contextual_first"], expected["contextual_second"]]
        and by_id[expected["critical_event"]]["review_urgency"] == "urgent"
        and exact["matched_nontechnical_record_ids"] == ["CTX-A"]
        and exact["business_context_record_id"] == "BIZ-A"
        and exact["review_urgency"] == "urgent"
        and exact["analyst_review_recommended"]
    )
    lab.check("green", "Exact workload and time correlation changes analyst review ordering",
              independent_priority,
              {"single_signal_order": severity_ids, "correlated_order": contextual_ids,
               "exact_join_ids": exact["matched_nontechnical_record_ids"],
               "business_context_id": exact["business_context_record_id"],
               "contextual_review_urgency": exact["review_urgency"]})

    mismatch = by_id[expected["mismatch_event"]]
    expired = by_id[expected["expired_event"]]
    time_event = next(row for row in fixture["technical_events"]
                      if row["event_id"] == expected["expired_event"])
    time_record = next(row for row in fixture["nontechnical_context"]
                       if row["record_id"] == "CTX-D-OUTSIDE-WINDOW")
    delta = abs((datetime.fromisoformat(time_record["observed_at"].replace("Z", "+00:00"))
                 - datetime.fromisoformat(time_event["observed_at"].replace("Z", "+00:00"))).total_seconds())
    same_workload_outside_window = (time_record["workload_id"] == time_event["workload_id"]
                                    and delta > fixture["correlation_window_seconds"])
    ambiguous = by_id[expected["ambiguous_event"]]
    safe_outputs = all(row["attribution"] == "not_assessed"
                       and row["employment_decision"] == "not_applicable" for row in contextual)
    comparators_rejected = (
        mismatch["matched_nontechnical_record_ids"] == []
        and mismatch["business_context_record_id"] is None
        and expired["matched_nontechnical_record_ids"] == []
        and same_workload_outside_window
        and expired["business_context_record_id"] is None
        and expired["business_context_status"] == "expired"
        and ambiguous["matched_nontechnical_record_ids"] == ["CTX-F"]
        and ambiguous["business_context_status"] == "ambiguous"
        and ambiguous["business_context_record_id"] is None
        and ambiguous["review_urgency"] == "routine"
    )
    evidence = {"single_signal": severity, "correlated": contextual,
                "fixture_notice": fixture["notice"],
                "correlation_window_seconds": fixture["correlation_window_seconds"]}
    (lab.evidence / "synthetic-triage-raw.json").write_text(json.dumps(evidence, indent=2) + "\n")
    lab.check("positive", "Out-of-scope, expired and ambiguously matched context cannot increase review urgency",
              comparators_rejected and safe_outputs,
              {"mismatch_excluded": not mismatch["matched_nontechnical_record_ids"],
               "same_workload_outside_time_window_excluded": same_workload_outside_window
                   and not expired["matched_nontechnical_record_ids"],
               "expired_context_excluded": expired["business_context_record_id"] is None,
               "expired_status": expired["business_context_status"],
               "ambiguous_status": ambiguous["business_context_status"],
               "no_attribution_or_employment_decision": safe_outputs})
