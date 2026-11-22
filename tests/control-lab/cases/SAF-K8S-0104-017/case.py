"""Exercise metadata admission for a synthetic CIS exception record."""
import json
from pathlib import Path
import time


HERE = Path(__file__).parent
FIXTURE = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
SCOPE = (
    "Kind API admission of synthetic ConfigMap exception records. The policy checks only "
    "required governance metadata and scheduled review deadlines against a fixed date. "
    "It cannot prove an authentic "
    "risk-owner decision, cross-functional review, implemented mitigation, or live reassessment."
)


def record(item):
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": item["name"],
            "labels": {FIXTURE["scope_label"]: "fixture"},
        },
        "data": item["data"],
    }


def install_policy(lab):
    lab.kubectl("label", "namespace", "saf-test", f"{FIXTURE['namespace_label']}=enabled")
    api = "admissionregistration.k8s.io/v1"
    required = [
        "cluster_scope", "benchmark", "benchmark_version", "kubernetes_version",
        "recommendation_id", "risk_owner_record", "justification",
        "compensating_controls", "review_due",
    ]
    expression = (
        "has(object.data) && "
        + " && ".join(f"'{key}' in object.data && object.data['{key}'].size() > 0" for key in required)
    )
    lab.create({
        "apiVersion": api,
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": FIXTURE["policy_name"]},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {
                "objectSelector": {"matchLabels": {FIXTURE["scope_label"]: "fixture"}},
                "resourceRules": [{
                    "apiGroups": [""],
                    "apiVersions": ["v1"],
                    "operations": ["CREATE", "UPDATE"],
                    "resources": ["configmaps"],
                }],
            },
            "validations": [{
                "expression": expression,
                "message": FIXTURE["denial_message"],
                "reason": "Forbidden",
            }, {
                "expression": (
                    "has(object.data) && 'review_due' in object.data "
                    "&& timestamp(object.data.review_due) >= timestamp('" + FIXTURE["as_of"] + "')"
                ),
                "message": FIXTURE["expired_message"],
                "reason": "Forbidden",
            }],
        },
    })
    lab.create({
        "apiVersion": api,
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": FIXTURE["policy_name"]},
        "spec": {
            "policyName": FIXTURE["policy_name"],
            "validationActions": ["Deny"],
            "matchResources": {
                "namespaceSelector": {
                    "matchLabels": {FIXTURE["namespace_label"]: "enabled"},
                },
            },
        },
    })


def run(lab):
    incomplete = record(FIXTURE["incomplete"])
    accepted = record(FIXTURE["accepted"])

    before = lab.create(incomplete, dry_run=True, allow_failure=True)
    lab.check(
        "red",
        "Incomplete synthetic exception metadata reaches admission before the policy is installed",
        before.returncode == 0,
        {"admitted": before.returncode == 0, "detail": before.stderr.strip()},
    )

    install_policy(lab)
    deadline = time.monotonic() + 20
    denied = lab.create(incomplete, dry_run=True, allow_failure=True)
    while FIXTURE["denial_message"] not in denied.stderr and time.monotonic() < deadline:
        time.sleep(0.5)
        denied = lab.create(incomplete, dry_run=True, allow_failure=True)
    lab.check(
        "green",
        "The same incomplete record is denied by the scoped admission policy",
        denied.returncode != 0
        and FIXTURE["denial_message"] in denied.stderr
        and FIXTURE["policy_name"] in denied.stderr,
        {"admitted": denied.returncode == 0,
         "policy_denial": FIXTURE["denial_message"] in denied.stderr,
         "correct_policy": FIXTURE["policy_name"] in denied.stderr},
    )

    complete_result = lab.create(accepted)
    lab.check(
        "positive",
        "Complete synthetic metadata remains admissible",
        complete_result.get("data") == accepted["data"],
        {"admitted_with_exact_metadata": complete_result.get("data") == accepted["data"]},
    )

    changed = lab.kubectl(
        "patch", "configmap", accepted["metadata"]["name"], "--type=merge",
        "--patch", json.dumps({"data": {"review_due": "2026-10-21T00:00:00Z"}}),
        "--dry-run=server", allow_failure=True,
    )
    overdue = changed.returncode != 0 and FIXTURE["expired_message"] in changed.stderr
    lab.check("green", "An update cannot set a review deadline earlier than the fixture date",
              overdue, {"rejected_as_overdue": overdue})

    current = json.loads(lab.kubectl("get", "configmap", accepted["metadata"]["name"], "-o", "json").stdout)
    unchanged = current["data"]["review_due"] == accepted["data"]["review_due"]
    lab.check("positive", "The accepted exception keeps its original review schedule",
              unchanged, {"original_deadline_preserved": unchanged})
