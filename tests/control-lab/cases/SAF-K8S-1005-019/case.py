"""Exercise disclosure intake and triage readiness with synthetic records only."""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
WORKER_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-test"
CONFIG_NAME = "saf-1005-019-fixtures"
JOB_NAME = "saf-1005-019-intake-check"
SCOPE = (
    "One disposable Kind v1.36.1 cluster and one digest-pinned, tokenless Python Job process only. "
    "The Job evaluates checked-in fictional policy metadata and invented report records using fixed "
    "timestamps; it makes no network calls and does not inspect any real policy, report, feed, target, "
    "contact channel, vulnerability, cluster, AI workload, or GPU. It validates policy-field presence, "
    "synthetic internal/external intake routing, stated mock scope, anonymous submission, and severity-tier "
    "acknowledgment/triage deadlines. It does not establish that a policy is actually published, a contact "
    "channel is monitored, an organization has authorized any real testing, or production teams meet SLAs."
)


def fixture(name):
    return (FIXTURES / name).read_text()


def expected_synthetic_ids():
    return ["SYN-REPORT-INTERNAL-001", "SYN-REPORT-EXTERNAL-ANON-001",
            "SYN-REPORT-MEDIUM-001", "SYN-REPORT-LOW-001"]


def run(lab):
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": CONFIG_NAME, "namespace": NAMESPACE,
                     "labels": {"saf-k8s.example/control-1005-019": "synthetic-fixture"}},
        "immutable": True,
        "data": {
            "worker.py": fixture("worker.py"),
            "policy.json": fixture("policy.json"),
            "reports.json": fixture("reports.json"),
        },
    })
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": JOB_NAME, "namespace": NAMESPACE,
                     "labels": {"saf-k8s.example/control-1005-019": "synthetic-fixture"}},
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": 90,
            "template": {
                "metadata": {"labels": {"saf-k8s.example/control-1005-019": "synthetic-fixture"}},
                "spec": {
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{
                        "name": "offline-intake-worker", "image": WORKER_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "/case/worker.py"],
                        "securityContext": {"allowPrivilegeEscalation": False,
                                             "readOnlyRootFilesystem": True,
                                             "capabilities": {"drop": ["ALL"]}},
                        "volumeMounts": [{"name": "fixture", "mountPath": "/case", "readOnly": True}],
                        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                      "limits": {"cpu": "250m", "memory": "64Mi"}},
                    }],
                    "volumes": [{"name": "fixture", "configMap": {
                        "name": CONFIG_NAME, "defaultMode": 292}}],
                },
            },
        },
    })
    lab.kubectl("wait", f"job/{JOB_NAME}", "--for=condition=complete", "--timeout=120s", timeout=130)
    raw = lab.kubectl("logs", f"job/{JOB_NAME}").stdout.strip()
    (lab.evidence / "intake-triage.raw.json").write_text(raw + "\n")
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as error:
        lab.block(f"Synthetic intake worker returned no machine-readable result ({error})")

    missing = result["missing_policy"]
    lab.check("red", "An absent published policy is identified as not ready",
              missing["ready"] is False and missing["reasons"] == ["policy_missing"], missing)

    overdue = result["overdue"]
    lab.check("red", "A synthetic high-severity report beyond its mock triage target is flagged",
              overdue["triage_within_target"] is False
              and overdue["status"] == "triage_sla_missed", overdue)

    readiness = result["readiness"]
    lab.check("green", "Complete mock policy and on-time in-scope samples pass all four severity tiers",
              readiness["ready"] is True
              and readiness["missing_fields"] == []
              and readiness["on_time_report_ids"] == expected_synthetic_ids()
              and readiness["late_report_ids"] == ["SYN-REPORT-HIGH-LATE-001"], readiness)

    routes = result["routing"]
    lab.check("positive", "Internal and anonymous external mock reports route through distinct declared channels",
              routes["accepted_report_ids"] == expected_synthetic_ids()
              and routes["anonymous_external_accepted"] is True
              and routes["out_of_scope_handled"] == "referral_only_no_testing_authorized"
              and routes["wrong_channel"] == "channel_mismatch",
              routes)
