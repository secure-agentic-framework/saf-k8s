"""Evaluate synthetic stage-based feature-gate governance records."""
import json
from datetime import date
from pathlib import Path
import time


HERE = Path(__file__).parent
FIXTURE = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
SCOPE = (
    "Kubernetes v1.36.1 stage metadata and synthetic governance records. A namespace-local "
    "admission example rejects incomplete test records and accepts complete records. "
    "Actual risk assessment, reviewer identity and production activation need separate evidence."
)
POLICY = "fixture-feature-review"
MESSAGE = "synthetic feature gate review is incomplete"
LABEL = "saf-k8s.example/feature-review"
ROLE_KEYS = {
    "Platform Engineering": "platform", "Security Engineering": "security",
    "Architecture Review": "architecture",
}
TRIGGER_KEYS = {
    "Kubernetes minor release": "minor", "feature-stage transition": "stage_change",
    "security incident": "incident", "expiry date": "expiry_revisit",
}


def evaluate(record, as_of):
    """Return a disposition and reasons; this is not an authorization decision."""
    reasons = []
    gate = FIXTURE["gates"].get(record.get("feature_gate"))
    if gate is None:
        return {"disposition": "reject", "reasons": ["unknown_feature_gate"]}
    if record.get("kubernetes_version") != gate["kubernetes_version"]:
        reasons.append("version_mismatch")
    if record.get("documented_stage") != gate["stage"]:
        reasons.append("stage_mismatch")
    if record.get("target") != "production":
        reasons.append("target_not_production")
    required_roles = list(FIXTURE["required_roles"])
    if gate["stage"] == "Alpha":
        required_roles.append("Architecture Review")
        if not record.get("alpha_production_exception"):
            reasons.append("missing_alpha_production_exception")

    if not record.get("change_id") or not record.get("risk_assessment_id"):
        reasons.append("missing_traceable_record")
    if not record.get("risk_summary") or not record.get("scope"):
        reasons.append("missing_risk_or_scope")
    approvals = record.get("approvals", [])
    roles = {entry.get("role") for entry in approvals if entry.get("record_id") and entry.get("approver")}
    for role in required_roles:
        if role not in roles:
            reasons.append("missing_or_untraceable_" + role.lower().replace(" ", "_"))

    try:
        expires = date.fromisoformat(record["expires_on"])
        today = date.fromisoformat(as_of)
        if expires <= today:
            reasons.append("approval_expired")
    except (KeyError, TypeError, ValueError):
        reasons.append("missing_or_invalid_expiry")

    required_triggers = set(FIXTURE["required_revisit_triggers"])
    actual_triggers = set(record.get("revisit_triggers", []))
    if not required_triggers.issubset(actual_triggers):
        reasons.append("incomplete_revisit_conditions")
    if record.get("reviewed_version") != record.get("kubernetes_version"):
        reasons.append("reviewed_version_not_bound_to_target")
    return {"disposition": "accept" if not reasons else "reject", "reasons": reasons}


def check_fixture_records(lab):
    cases = FIXTURE["scenarios"]
    for scenario in cases:
        observed = evaluate(scenario["record"], FIXTURE["as_of"])
        expected = scenario["expected"]
        lab.check(
            "positive" if expected["disposition"] == "accept" else "green",
            scenario["name"],
            observed == expected,
            {"as_of": FIXTURE["as_of"], "observed": observed, "expected": expected,
             "feature_gate": scenario["record"].get("feature_gate"),
             "governance_decision_is_synthetic": True},
        )


def configmap(index, record):
    data = {key: record[key] for key in (
        "feature_gate", "kubernetes_version", "reviewed_version", "documented_stage",
        "target", "change_id", "risk_assessment_id", "risk_summary", "scope", "expires_on",
    )}
    for approval in record["approvals"]:
        if approval["approver"] and approval["record_id"]:
            data[ROLE_KEYS[approval["role"]]] = approval["record_id"]
    data.update({TRIGGER_KEYS[trigger]: "yes" for trigger in record["revisit_triggers"]})
    if record.get("alpha_production_exception"):
        data["exception"] = record["alpha_production_exception"]
    return {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": f"synthetic-review-{index}", "labels": {LABEL: "fixture"}},
        "data": data,
    }


def install_policy(lab):
    lab.kubectl("label", "namespace", "saf-test", f"{LABEL}=enabled")
    api = "admissionregistration.k8s.io/v1"
    at = FIXTURE["as_of"]
    expression = (
        "has(object.data) && "
        "['feature_gate','documented_stage','kubernetes_version','reviewed_version','target',"
        "'change_id','risk_assessment_id','risk_summary','scope','expires_on','platform','security',"
        "'minor','stage_change','incident','expiry_revisit'].all(k, k in object.data && object.data[k] != '') && "
        "object.data.target == 'production' && object.data.kubernetes_version == 'v1.36.1' && "
        "object.data.reviewed_version == object.data.kubernetes_version && "
        f"timestamp(object.data.expires_on + 'T00:00:00Z') > timestamp('{at}T00:00:00Z') && "
        "((object.data.feature_gate == 'PodLevelResources' && object.data.documented_stage == 'Beta') || "
        "(object.data.feature_gate == 'ContainerStopSignals' && object.data.documented_stage == 'Alpha' && "
        "['architecture','exception'].all(k, k in object.data && object.data[k] != '')))"
    )
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail",
                         "matchConstraints": {"objectSelector": {"matchLabels": {LABEL: "fixture"}},
                                              "resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                                 "operations": ["CREATE"],
                                                                 "resources": ["configmaps"]}]},
                         "validations": [{"expression": expression, "message": MESSAGE, "reason": "Forbidden"}]}})
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"],
                         "matchResources": {"namespaceSelector": {"matchLabels": {LABEL: "enabled"}}}}})


def run(lab):
    check_fixture_records(lab)
    scenarios = FIXTURE["scenarios"]
    records = [configmap(index, s["record"]) for index, s in enumerate(scenarios)]
    baseline = lab.create(records[0], dry_run=True, allow_failure=True)
    lab.check("red", "The incomplete alpha example reaches admission before validation exists",
              baseline.returncode == 0, {"admitted": baseline.returncode == 0})
    install_policy(lab)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        result = lab.create(records[0], dry_run=True, allow_failure=True)
        if MESSAGE in result.stderr:
            break
        time.sleep(0.5)
    for item, scenario in zip(records, scenarios):
        result = lab.create(item, dry_run=True, allow_failure=True)
        expected = scenario["expected"]["disposition"] == "accept"
        matched = result.returncode == 0 if expected else result.returncode != 0 and MESSAGE in result.stderr
        lab.check("positive" if expected else "green", f"API admission reproduces {scenario['name']}",
                  matched, {"admitted": result.returncode == 0, "policy_denial": MESSAGE in result.stderr,
                            "detail": "" if matched else result.stderr.strip()})

    alpha = configmap(5, scenarios[0]["record"])
    alpha["data"].update(architecture="APR-SYN-ARCH", exception="EX-SYN-ALPHA")
    admitted = lab.create(alpha, dry_run=True, allow_failure=True)
    lab.check("positive", "An alpha record with the additional exception and architecture review is admitted",
              admitted.returncode == 0, {"admitted": admitted.returncode == 0,
                                         "detail": admitted.stderr.strip()})
