"""Native admission gate joining an inert response action to a retained decision."""

import json
import time

API = "admissionregistration.k8s.io/v1"
RBAC = "rbac.authorization.k8s.io"
APPS = "apps"
OWNER = "fixture-response-reviewer"
OBSERVER = "fixture-monitor-observer"
NAMESPACE = "saf-test"
DECISION = "fixture-decision-corroborated"
HOLD_DECISION = "fixture-decision-observe"
TARGET = "fixture-response-target"
COMPARATOR = "fixture-response-comparator"
POLICY = "fixture-response-action-approval"
BINDING = "fixture-response-action-approval"
ROLE = "fixture-response-action"
REVIEW_ANNOTATION = "fixture.example/review-id"
WORKLOAD_LABEL = "fixture.example/workload-class"
DENIAL_REVIEWER = "Fixture response requires the accountable reviewer identity"
DENIAL_TARGET = "Fixture response is limited to the designated target"
DENIAL_DECISION = "Fixture response requires the retained corroborated escalation"
DENIAL_REFERENCE = "Fixture response must reference the exact retained decision"
DENIAL_WORKLOAD = "Fixture response workload class must match the retained decision"
DENIAL_SHAPE = "Fixture response preserves all other Deployment spec fields"
DENIAL_SCALE = "Fixture response permits only the bounded scale-to-zero action"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"


def deployment(name, *, workload_class):
    container = {"name": "inert", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                 "command": ["python", "-c", "import time; time.sleep(360)"],
                 "resources": {"requests": {"cpu": "5m", "memory": "20Mi"},
                               "limits": {"cpu": "50m", "memory": "48Mi"}},
                 "securityContext": {"allowPrivilegeEscalation": False,
                                     "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}}}
    pod_spec = {"automountServiceAccountToken": False,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                    "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [container]}
    return {"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": name, "labels": {"app": name, WORKLOAD_LABEL: workload_class}},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": name}},
                     "template": {"metadata": {"labels": {"app": name, WORKLOAD_LABEL: workload_class}},
                                  "spec": pod_spec}}}


def install(lab, decision_uid):
    preserved = ("selector", "template", "strategy", "minReadySeconds",
                 "revisionHistoryLimit", "paused", "progressDeadlineSeconds")
    unchanged = " && ".join(
        f"has(object.spec.{field}) == has(oldObject.spec.{field}) && "
        f"(!has(object.spec.{field}) || object.spec.{field} == oldObject.spec.{field})"
        for field in preserved
    )
    validations = [
        {"expression": f"request.userInfo.username == '{OWNER}'", "message": DENIAL_REVIEWER},
        {"expression": f"object.metadata.name == '{TARGET}'", "message": DENIAL_TARGET},
        {"expression": (f"params != null && params.metadata.name == '{DECISION}' && "
                        f"params.metadata.uid == '{decision_uid}' && has(params.data) && "
                        "params.data['disposition'] == 'escalate' && params.data['signal'] == 'high' && "
                        "params.data['workload'] == 'unapproved' && params.data['corroboration'] == 'verified-fixture'"),
         "message": DENIAL_DECISION},
        {"expression": f"has(object.metadata.annotations) && object.metadata.annotations['{REVIEW_ANNOTATION}'] == params.metadata.name",
         "message": DENIAL_REFERENCE},
        {"expression": f"has(object.metadata.labels) && object.metadata.labels['{WORKLOAD_LABEL}'] == params.data['workload']",
         "message": DENIAL_WORKLOAD},
        {"expression": "object.spec.replicas == 0", "message": DENIAL_SCALE},
        {"expression": unchanged, "message": DENIAL_SHAPE},
    ]
    lab.create({"apiVersion": API, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail", "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
                         "matchConstraints": {"resourceRules": [{"apiGroups": [APPS], "apiVersions": ["v1"],
                                                                  "operations": ["UPDATE"], "resources": ["deployments"],
                                                                  "scope": "Namespaced"}]},
                         "matchConditions": [{"name": "fixture-targets-only",
                                               "expression": f"object.metadata.name in ['{TARGET}', '{COMPARATOR}']"}],
                         "validations": validations}})
    lab.create({"apiVersion": API, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": BINDING},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"],
                         "paramRef": {"name": DECISION, "namespace": NAMESPACE, "parameterNotFoundAction": "Deny"},
                         "matchResources": {"namespaceSelector": {"matchLabels": {"fixture.example/incident-review": "true"}}}}})


def wait_policy_ready(lab, timeout=25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = lab.kubectl("get", "validatingadmissionpolicy", POLICY, "-o", "json")
        checking = json.loads(response.stdout).get("status", {}).get("typeChecking")
        if checking is not None:
            warnings = checking.get("expressionWarnings", [])
            if warnings:
                lab.block("The response admission policy has CEL type-check warnings")
            return
        time.sleep(0.25)
    lab.block("The response admission policy did not report CEL type-check results")


def patch_attempt(lab, subject, name, *, decision_id, dry_run=True, change_extra_field=False):
    patch = {"metadata": {"annotations": {REVIEW_ANNOTATION: decision_id}}, "spec": {"replicas": 0}}
    if change_extra_field:
        patch["spec"]["minReadySeconds"] = 7
    args = ["--as", subject, "patch", "deployment", name, "--type=merge", "-p", json.dumps(patch), "-o", "json"]
    if dry_run:
        args.append("--dry-run=server")
    return lab.kubectl(*args, allow_failure=True)


def policy_denied(result, message):
    text = result.stderr or ""
    return result.returncode != 0 and POLICY in text and message in text


def observe_expected(lab, subject, name, decision_id, *, expected_message=None, change_extra_field=False, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = patch_attempt(lab, subject, name, decision_id=decision_id, change_extra_field=change_extra_field)
        if expected_message and policy_denied(result, expected_message):
            return True
        if expected_message is None and result.returncode == 0:
            return True
        time.sleep(0.4)
    return False


def current_deployment(lab, name):
    return json.loads(lab.kubectl("get", "deployment", name, "-o", "json").stdout)


def available_state(obj):
    return {"uid": obj.get("metadata", {}).get("uid", ""),
            "desired": obj.get("spec", {}).get("replicas", 1),
            "replicas": obj.get("status", {}).get("replicas", 0),
            "ready": obj.get("status", {}).get("readyReplicas", 0)}


def run(lab):
    decision = json.loads(lab.kubectl("get", "configmap", DECISION, "-o", "json").stdout)
    data = decision.get("data", {})
    decision_bound = (decision.get("immutable") is True and bool(decision.get("metadata", {}).get("uid"))
                      and decision["metadata"].get("name") == DECISION
                      and decision["metadata"].get("namespace") == NAMESPACE
                      and data == {"disposition": "escalate", "workload": "unapproved", "signal": "high",
                                   "corroboration": "verified-fixture"})
    if not decision_bound:
        lab.block("The response gate requires the exact retained corroborated escalation record")

    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "Role", "metadata": {"name": ROLE},
                "rules": [{"apiGroups": [APPS], "resources": ["deployments"],
                           "resourceNames": [TARGET, COMPARATOR], "verbs": ["get", "patch"]},
                          {"apiGroups": [""], "resources": ["configmaps"],
                           "resourceNames": [DECISION], "verbs": ["get"]}]})
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "RoleBinding", "metadata": {"name": ROLE},
                "roleRef": {"apiGroup": RBAC, "kind": "Role", "name": ROLE},
                "subjects": [{"apiGroup": RBAC, "kind": "User", "name": user} for user in (OWNER, OBSERVER)]})
    for obj in (deployment(TARGET, workload_class="unapproved"), deployment(COMPARATOR, workload_class="unapproved")):
        lab.create(obj)
    lab.kubectl("wait", "--for=condition=Available", "deployment/" + TARGET, "--timeout=65s", timeout=70)
    lab.kubectl("wait", "--for=condition=Available", "deployment/" + COMPARATOR, "--timeout=65s", timeout=70)
    before_target = available_state(current_deployment(lab, TARGET))
    before_comparator = available_state(current_deployment(lab, COMPARATOR))
    if not (before_target["uid"] and before_comparator["uid"] and before_target["desired"] == before_target["ready"] == 1
            and before_comparator["desired"] == before_comparator["ready"] == 1):
        lab.block("Both isolated response fixture Deployments must be available before the action")
    install(lab, decision["metadata"]["uid"])
    wait_policy_ready(lab)

    observer_denied = observe_expected(lab, OBSERVER, TARGET, DECISION, expected_message=DENIAL_REVIEWER)
    wrong_record_denied = observe_expected(lab, OWNER, TARGET, HOLD_DECISION, expected_message=DENIAL_REFERENCE)
    comparator_denied = observe_expected(lab, OWNER, COMPARATOR, DECISION, expected_message=DENIAL_TARGET)
    extra_spec_denied = observe_expected(lab, OWNER, TARGET, DECISION, expected_message=DENIAL_SHAPE,
                                         change_extra_field=True)
    approved_allowed = observe_expected(lab, OWNER, TARGET, DECISION)
    if not (observer_denied and wrong_record_denied and comparator_denied and extra_spec_denied and approved_allowed):
        lab.block("The response VAP did not produce all exact policy-specific decisions")

    applied = patch_attempt(lab, OWNER, TARGET, decision_id=DECISION, dry_run=False)
    if applied.returncode:
        lab.block("The authorized inert response action failed")
    deadline = time.monotonic() + 30
    after_target = after_comparator = {}
    while time.monotonic() < deadline:
        after_target = available_state(current_deployment(lab, TARGET))
        after_comparator = available_state(current_deployment(lab, COMPARATOR))
        if after_target["desired"] == after_target["replicas"] == after_target["ready"] == 0:
            break
        time.sleep(0.5)
    target_scaled_down = (after_target.get("uid") == before_target["uid"] and after_target.get("desired") == 0
                          and after_target.get("replicas") == 0 and after_target.get("ready") == 0)
    comparator_unchanged = (after_comparator.get("uid") == before_comparator["uid"]
                            and after_comparator.get("desired") == after_comparator.get("ready") == 1)
    passed = decision_bound and observer_denied and wrong_record_denied and comparator_denied and extra_spec_denied and approved_allowed and target_scaled_down and comparator_unchanged
    lab.check("response", "Only the accountable reviewer can apply the narrowly scoped action authorized by the retained corroborated decision",
              passed, {"exact_retained_decision_bound": decision_bound,
                       "observer_policy_denied": observer_denied,
                       "observer_denial_cause": DENIAL_REVIEWER,
                       "wrong_decision_reference_policy_denied": wrong_record_denied,
                       "wrong_decision_denial_cause": DENIAL_REFERENCE,
                       "comparator_policy_denied": comparator_denied,
                       "comparator_denial_cause": DENIAL_TARGET,
                       "unrelated_spec_change_policy_denied": extra_spec_denied,
                       "approved_target_action_admitted": approved_allowed,
                       "target_same_uid_scaled_to_zero": target_scaled_down,
                       "distinct_comparator_unchanged": comparator_unchanged})
    (lab.evidence / "fixture-response-action.json").write_text(json.dumps({
        "decision_uid": decision["metadata"]["uid"], "decision_name": DECISION,
        "target_before": before_target, "target_after": after_target,
        "comparator_before": before_comparator, "comparator_after": after_comparator,
        "observer_policy_denied": observer_denied,
        "wrong_decision_reference_policy_denied": wrong_record_denied,
        "comparator_policy_denied": comparator_denied,
        "unrelated_spec_change_policy_denied": extra_spec_denied,
        "approved_target_action_admitted": approved_allowed,
        "target_same_uid_scaled_to_zero": target_scaled_down,
        "distinct_comparator_unchanged": comparator_unchanged,
        "device_or_real_workload_action": False,
    }, indent=2) + "\n")
