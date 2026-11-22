"""Evaluate technique-aligned rules against inert synthetic audit records."""
import hashlib
import json
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
PROMETHEUS_IMAGE = (
    "docker.io/prom/prometheus:v3.16.0@sha256:"
    "e04987641b57704f408e31f6373ba4138ecf27cb4a165d24aabb6c38fddd0f06"
)
CONFIG = "saf-1003-005-fixtures"
JOB_PREFIX = "saf-1003-005-"
SCOPE = (
    "Kubernetes v1.36.1 Kind runs the pinned Prometheus 3.16.0 promtool rule evaluator "
    "on inert synthetic audit-event records. Two case-owned rules cover only privileged "
    "AI-namespace Pod creation (T1610) and Pod exec requests (T1609); unit-rule tests "
    "include positive matches, safe near misses, and a no-rule red comparator. A reviewed "
    "change record is checked against the rule IDs and versioned ATT&CK metadata. Production telemetry, "
    "alert delivery and analyst response require deployment evidence."
)


def _event_series(event):
    labels = ("event_id", "namespace", "verb", "resource", "privileged")
    parts = [f'{key}="{event[key]}"' for key in labels if key in event]
    return {"series": "saf_k8s_audit_event{" + ",".join(parts) + "}", "values": "1 1"}


def _group(name, events, expected):
    return {
        "name": name,
        "input_series": [_event_series(event) for event in events],
        "alert_rule_test": [{"eval_time": "1m", "alertname": alert,
                             "exp_alerts": alert_rows}
                            for alert, alert_rows in expected.items()],
    }


def _expected(rule_id, technique_id, event, summary, action, runbook):
    labels = {key: event[key] for key in
              ("event_id", "namespace", "verb", "resource", "privileged")
              if key in event}
    labels.update({"rule_id": rule_id, "technique_id": technique_id, "severity": "warning"})
    return {"exp_labels": labels,
            "exp_annotations": {"summary": summary, "action": action, "runbook": runbook}}


def _job(lab, name, test_file):
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "labels": {"saf-case": "1003-005"}},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90,
                  "template": {"metadata": {"labels": {"saf-case": "1003-005"}},
                               "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                                        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                            "seccompProfile": {"type": "RuntimeDefault"}},
                                        "containers": [{"name": "promtool", "image": PROMETHEUS_IMAGE,
                                                        "command": ["/bin/promtool", "test", "rules",
                                                                    "/fixture/" + test_file],
                                                        "securityContext": {"allowPrivilegeEscalation": False,
                                                                            "capabilities": {"drop": ["ALL"]}},
                                                        "volumeMounts": [{"name": "fixtures", "mountPath": "/fixture",
                                                                          "readOnly": True}]}],
                                        "volumes": [{"name": "fixtures", "configMap": {"name": CONFIG}}]}}},
    })
    deadline = time.monotonic() + 95
    while time.monotonic() < deadline:
        state = json.loads(lab.kubectl("get", "job", name, "-o", "json", timeout=15).stdout)
        terminal = [c for c in state.get("status", {}).get("conditions", [])
                    if c.get("status") == "True" and c.get("type") in {"Complete", "Failed"}]
        if terminal:
            break
        time.sleep(1)
    else:
        lab.block(f"promtool Job {name} did not complete")
    logs = lab.kubectl("logs", f"job/{name}", timeout=15).stdout
    pods = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={name}", "-o", "json", timeout=15).stdout)
    pod, = pods["items"]
    if not any(ref["uid"] == state["metadata"]["uid"] and ref.get("controller")
               for ref in pod["metadata"].get("ownerReferences", [])):
        lab.block("The evaluator Pod is not controlled by the expected Job")
    code = pod["status"]["containerStatuses"][0]["state"]["terminated"]["exitCode"]
    return {"pod_uid": pod["metadata"]["uid"], "exit_code": code,"job": name, "uid": state["metadata"]["uid"], "condition": terminal[0]["type"],
            "logs": logs, "passed": terminal[0]["type"] == "Complete"}


def run(lab):
    version = json.loads(lab.kubectl("version", "-o", "json").stdout)
    server = version.get("serverVersion", {}).get("gitVersion", "")
    if not server.startswith("v1.36."):
        lab.block(f"Expected a Kubernetes v1.36 server, got {server!r}")

    events = json.loads((HERE / "fixtures" / "events.json").read_text())
    metadata = json.loads((HERE / "fixtures" / "mitre-containers-v20.1.json").read_text())
    review = json.loads((HERE / "fixtures" / "change-review.json").read_text())
    by_id = {item["event_id"]: item for item in events}
    rule_ids = {rule["rule_id"] for rule in metadata["rules"]}
    techniques = {item["technique_id"] for item in metadata["rules"]}
    review_valid = (
        review["status"] == "example-reviewed" and review["reviewer_role"] == "Detection Engineering"
        and set(review["rule_ids"]) == rule_ids
        and set(review["technique_ids"]) == techniques
        and review["required_checks"] == ["positive-match", "near-miss", "ATT&CK-version-check"]
        and len(by_id) == len(events) and set(by_id) == {"evt-synthetic-privileged-ai-pod", "evt-synthetic-ai-pod-exec",
                          "evt-synthetic-safe-ai-pod", "evt-synthetic-read-ai-pod",
                          "evt-synthetic-privileged-ai-pod-outside", "evt-synthetic-ai-pod-exec-outside"}
    )
    configs = {
        "rules.yml": (HERE / "rules.yml").read_text(),
    }
    alerts = {
        "PrivilegedAIWorkloadRequest": [_expected(
            "SAF-K8S-RULE-1003-005-01", "T1610", by_id["evt-synthetic-privileged-ai-pod"],
            "Privileged AI namespace Pod request observed",
            "Review the Kubernetes audit record, workload owner, exception approval, and node exposure; follow the local response procedure.",
            "RB-IR-K8S-AI-PRIVILEGED-WORKLOAD")],
        "AIContainerExecRequest": [_expected(
            "SAF-K8S-RULE-1003-005-02", "T1609", by_id["evt-synthetic-ai-pod-exec"],
            "Container administration request targets an AI namespace Pod",
            "Check the authenticated principal, approval context, target workload, and related audit events; follow the local response procedure.",
            "RB-IR-K8S-AI-CONTAINER-ADMIN")],
    }
    groups = [
        _group("positive-privileged-workload", [by_id["evt-synthetic-privileged-ai-pod"]],
               {"PrivilegedAIWorkloadRequest": alerts["PrivilegedAIWorkloadRequest"]}),
        _group("positive-container-exec-request", [by_id["evt-synthetic-ai-pod-exec"]],
               {"AIContainerExecRequest": alerts["AIContainerExecRequest"]}),
        _group("near-miss-safe-workload-and-read", [by_id["evt-synthetic-safe-ai-pod"],
                                                     by_id["evt-synthetic-read-ai-pod"],
                                                     by_id["evt-synthetic-privileged-ai-pod-outside"],
                                                     by_id["evt-synthetic-ai-pod-exec-outside"]],
               {"PrivilegedAIWorkloadRequest": [], "AIContainerExecRequest": []}),
    ]
    configs["without-rules.json"] = json.dumps({"rule_files": [], "evaluation_interval": "1m",
                                                 "tests": groups[:2]}, indent=2) + "\n"
    configs["with-rules.json"] = json.dumps({"rule_files": ["rules.yml"], "evaluation_interval": "1m",
                                              "tests": groups}, indent=2) + "\n"
    rules_text = configs["rules.yml"]
    review_rules_present = all(
        rule["rule_id"] in rules_text and rule["technique_id"] in rules_text
        for rule in metadata["rules"]
    )
    actionable_fields_present = all(
        needle in rules_text for needle in (
            "summary:", "action:", "runbook:",
            "RB-IR-K8S-AI-PRIVILEGED-WORKLOAD", "RB-IR-K8S-AI-CONTAINER-ADMIN",
        )
    )
    rule_digest = hashlib.sha256(rules_text.encode()).hexdigest()
    runbooks = json.loads((HERE / "runbooks.json").read_text())
    expected_runbooks = {row["exp_annotations"]["runbook"]
                         for alerts_for_rule in alerts.values() for row in alerts_for_rule}
    review_valid = (
        review_valid and metadata["release"] == "20.1" and review["attack_release"] == "v20.1"
        and review["rules_sha256"] == rule_digest and review_rules_present and actionable_fields_present
        and set(runbooks) == expected_runbooks and all(row["owner"] and row["triage"] for row in runbooks.values())
        and all("Containers" in row["platforms"] and row["tactic_id"] == "TA0002" for row in metadata["rules"])
        and all("technique_id" not in event for event in events)
    )
    lab.check("green", "The versioned ATT&CK change review matches rule labels and both IDs",
              review_valid, {"review_id": review.get("review_id"), "review_rules_present": review_rules_present,
                             "actionable_fields_present": actionable_fields_present,
                             "attack_release": review.get("attack_release")})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CONFIG}, "data": configs})

    red = _job(lab, JOB_PREFIX + "red", "without-rules.json")
    expected_red = red["condition"] == "Failed" and red["exit_code"] == 1 and all(name in red["logs"] for name in alerts)
    lab.check("red", "Both synthetic request signals lack actionable matches when the rule file is absent",
              expected_red, {"job": red["job"], "expected_missing-alert": expected_red,
                             "rule_evaluator_exit": red["condition"]})

    green = _job(lab, JOB_PREFIX + "rules", "with-rules.json")
    evidence = {"no_rule_job": red, "rule_job": green, "events": events,
                "fixture_groups": groups, "technique_metadata": metadata, "review": review,
                "reviewed_rule_digest": rule_digest, "runbooks": runbooks}
    (lab.evidence / "detector-evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    matches = green["passed"] and green["exit_code"] == 0 and len(groups) == 3 and all(
        group["name"] in {"positive-privileged-workload", "positive-container-exec-request",
                          "near-miss-safe-workload-and-read"} for group in groups
    )
    lab.check("green", "Prometheus matches both prioritized synthetic behaviors and leaves safe near misses quiet",
              green["passed"] and matches,
              {"job": green["job"], "rule_engine_passed": green["passed"],
               "expected_rule_ids": sorted(rule_ids), "groups": [group["name"] for group in groups]})
    benign = "near-miss-safe-workload-and-read" in {group["name"] for group in groups} and green["passed"]
    lab.check("positive", "Safe in-scope requests and identical outside-scope signals produce no alert",
              benign, {"safe_near_misses": 4, "unexpected_alerts": 0 if benign else None})
