"""Verify accountable review of synthetic accelerator incident decisions."""

import json
import time

SCOPE = "Real Kubernetes RBAC and admission over synthetic decisions plus one inert fixture-only scale-to-zero response; no accelerator action."
API = "admissionregistration.k8s.io/v1"
RBAC = "rbac.authorization.k8s.io"
NAME = "fixture-incident-review"
SCOPE_LABEL = "fixture.example/incident-review"
OWNER = "fixture-response-reviewer"
OBSERVER = "fixture-monitor-observer"
MESSAGE = "Fixture escalation requires corroborated evidence and an authorized reviewer"


def record(name, disposition, workload, signal, corroboration):
    return {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": f"fixture-decision-{name}"},
            "immutable": True, "data": {"disposition": disposition, "workload": workload,
                                        "signal": signal, "corroboration": corroboration}}


def submit(lab, subject, body, *, dry_run=True):
    flags = ["--dry-run=server"] if dry_run else []
    return lab.kubectl("--as", subject, "create", "-f", "-", "-o", "json", *flags,
                       payload=json.dumps(body), allow_failure=True)


def enforce(lab):
    lab.create({"apiVersion": API, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": NAME},
                "spec": {"failurePolicy": "Fail", "matchConstraints": {"resourceRules": [{
                    "apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["configmaps"],
                }]}, "matchConditions": [{"name": "incident-record", "expression":
                    "object.metadata.name.startsWith('fixture-decision-')"}], "validations": [{
                    "expression": "has(object.data) && 'disposition' in object.data && "
                                  "(object.data.disposition == 'hold' || "
                                  "(object.data.disposition == 'escalate' && "
                                  f"request.userInfo.username == '{OWNER}' && "
                                  "'signal' in object.data && object.data.signal == 'high' && "
                                  "'workload' in object.data && object.data.workload == 'unapproved' && "
                                  "'corroboration' in object.data && object.data.corroboration == 'verified-fixture'))",
                    "message": MESSAGE,
                }]}})
    lab.create({"apiVersion": API, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": NAME},
                "spec": {"policyName": NAME, "validationActions": ["Deny"], "matchResources": {
                    "namespaceSelector": {"matchLabels": {SCOPE_LABEL: "true"}}}}})


def denied(result):
    return result.returncode != 0 and MESSAGE in result.stderr


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", f"{SCOPE_LABEL}=true")
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "Role", "metadata": {"name": NAME},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["create"]}]})
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "RoleBinding", "metadata": {"name": NAME},
                "roleRef": {"apiGroup": RBAC, "kind": "Role", "name": NAME},
                "subjects": [{"apiGroup": RBAC, "kind": "User", "name": user} for user in (OWNER, OBSERVER)]})
    high_only = record("high-only", "escalate", "unknown", "high", "missing")
    baseline = submit(lab, OBSERVER, high_only).returncode == 0
    lab.check("red", "A high-only escalation record is admitted before reviewed admission is enabled", baseline,
              {"high_only_escalation_initially_admitted": baseline})
    enforce(lab)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if denied(submit(lab, OBSERVER, high_only)):
            break
        time.sleep(0.4)
    else:
        lab.block("Kubernetes did not enforce the expected incident admission decision")

    approved_high = record("approved", "escalate", "approved", "high", "verified-fixture")
    escalation = record("corroborated", "escalate", "unapproved", "high", "verified-fixture")
    missing = denied(submit(lab, OWNER, high_only))
    benign = denied(submit(lab, OWNER, approved_high))
    wrong_reviewer = denied(submit(lab, OBSERVER, escalation))
    lab.check("green", "Admission rejects missing attribution, approved workload escalation, and an unauthorized reviewer",
              missing and benign and wrong_reviewer,
              {"missing_attribution_denied": missing, "approved_workload_escalation_denied": benign,
               "unauthorized_reviewer_denied": wrong_reviewer})

    observe = record("observe", "hold", "unknown", "high", "missing")
    hold_result = submit(lab, OBSERVER, observe, dry_run=False)
    review_result = submit(lab, OWNER, escalation, dry_run=False)
    expected = {entry["metadata"]["name"]: entry["data"]["disposition"] for entry in (observe, escalation)}
    stored = {}
    if hold_result.returncode == review_result.returncode == 0:
        for key in expected:
            item = json.loads(lab.kubectl("get", "configmap", key, "-o", "json").stdout)
            stored[key] = item["data"]["disposition"]
    lab.check("positive", "An observer can retain a hold and the authorized reviewer can retain a corroborated escalation",
              stored == expected, stored)
    (lab.evidence / "accelerator-triage-observations.json").write_text(json.dumps({
        "decisions": stored, "hardware_or_attack_tested": False, "disruptive_action_performed": False,
    }, indent=2) + "\n")

    # Add one inert native response-action check after the original three checks.
    import importlib.util as _importlib_util
    from pathlib import Path as _Path
    _response_spec = _importlib_util.spec_from_file_location(
        "response_action", _Path(__file__).with_name("response_action.py"))
    _response_action = _importlib_util.module_from_spec(_response_spec)
    _response_spec.loader.exec_module(_response_action)
    _response_action.run(lab)
