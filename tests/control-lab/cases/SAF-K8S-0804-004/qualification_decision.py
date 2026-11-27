"""Native qualification-decision record and exact-profile deferral gate."""

import hashlib
import json
import time

API = "admissionregistration.k8s.io/v1"
RBAC = "rbac.authorization.k8s.io"
NAMESPACE = "saf-test"
RUNTIME = "fixture-reviewed-runtime"
REVIEWER = "fixture-qualification-reviewer"
OBSERVER = "fixture-qualification-observer"
DECISION = "fixture-qualification-decision"
DECISION_POLICY = "fixture-qualification-record-policy"
DECISION_BINDING = "fixture-qualification-record-policy"
POD_POLICY = "fixture-qualification-profile-policy"
POD_BINDING = "fixture-qualification-profile-policy"
ROLE = "fixture-qualification-decision-writer"
PROFILE_LABEL = "fixture.example/qualification-profile"
DECISION_ANNOTATION = "fixture.example/qualification-decision"
PROFILE_HASH_ANNOTATION = "fixture.example/qualification-profile-sha256"
DEFERRED_PROFILE = "fixture-with-overhead"
BASELINE_PROFILE = "fixture-standard"
RECORD_DENIAL = "A deferral record must be authorized, evidence-bound, and include its compensating control and reassessment criteria"
PROFILE_DENIAL = "The retained qualification decision defers this exact profile"
COMPENSATING = "admission-deny-pods-for-fixture-with-overhead-profile"
REASSESS = "Reassess when the protected runtime and attestation path are approved and a representative protected measurement is recorded; also reassess after runtime, device, firmware, driver, operator, or workload changes"


def _q(value):
    return json.dumps(str(value))


def _policy_ready(lab, name, timeout=25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = lab.kubectl("get", "validatingadmissionpolicy", name, "-o", "json")
        checking = json.loads(result.stdout).get("status", {}).get("typeChecking")
        if checking is not None:
            if checking.get("expressionWarnings"):
                lab.block("The qualification fixture admission policy has CEL type-check warnings")
            return
        time.sleep(0.25)
    lab.block("The qualification fixture policy did not report CEL type-check results")


def _role(lab):
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "Role", "metadata": {"name": ROLE},
                "rules": [{"apiGroups": [""], "resources": ["configmaps", "pods"], "verbs": ["create"]},
                          {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [DECISION],
                           "verbs": ["get"]}]})
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "RoleBinding", "metadata": {"name": ROLE},
                "roleRef": {"apiGroup": RBAC, "kind": "Role", "name": ROLE},
                "subjects": [{"apiGroup": RBAC, "kind": "User", "name": user}
                             for user in (REVIEWER, OBSERVER)]})


def _denied(result, policy, message):
    text = result.stderr or ""
    return result.returncode != 0 and policy in text and message in text


def _submit(lab, subject, obj, *, dry_run=True):
    args = ["--as", subject, "create", "-f", "-", "-o", "json"]
    if dry_run:
        args.append("--dry-run=server")
    return lab.kubectl(*args, payload=json.dumps(obj, sort_keys=True), allow_failure=True)


def _wait_for_policy_decision(lab, subject, candidate, policy, message):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        result = _submit(lab, subject, candidate)
        if _denied(result, policy, message):
            return result
        if result.returncode:
            lab.block(f"Unexpected server decision before {policy} became active")
        time.sleep(0.5)
    lab.block(f"The live dry-run request did not observe the expected decision from {policy}")


def _decision_policy(lab, expected_data, profile_hash):
    expected = dict(expected_data)
    expected["profile_sha256"] = profile_hash
    fields = ["decision", "profile", "profile_sha256", "run_pod_uid", "run_image_id_sha256",
              "run_result_sha256", "baseline_result_sha256", "runtime_class", "protected_measurement",
              "runtime_handler", "approver", "compensating_control", "reassessment_criteria", "scope"]
    exact_data = [f"'{key}' in object.data && object.data[{_q(key)}] == {_q(expected[key])}" for key in fields]
    expression = "has(object.data) && object.data.size() == " + str(len(fields)) + " && " + " && ".join(exact_data)
    expression += (f" && object.immutable == true && request.userInfo.username == {_q(REVIEWER)}")
    lab.create({"apiVersion": API, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": DECISION_POLICY},
                "spec": {"failurePolicy": "Fail",
                         "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                                    "operations": ["CREATE"], "resources": ["configmaps"],
                                                                    "scope": "Namespaced"}]},
                         "matchConditions": [{"name": "exact-qualification-decision",
                                               "expression": f"object.metadata.name == {_q(DECISION)}"}],
                         "validations": [{"expression": expression, "message": RECORD_DENIAL}]}})
    lab.create({"apiVersion": API, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": DECISION_BINDING},
                "spec": {"policyName": DECISION_POLICY, "validationActions": ["Deny"],
                         "matchResources": {"namespaceSelector": {"matchLabels": {
                             "kubernetes.io/metadata.name": NAMESPACE}}}}})


def _pod_policy(lab):
    expression = " && ".join((
        "params != null", "has(params.data)", f"params.metadata.name == {_q(DECISION)}",
        "params.data['decision'] == 'defer'",
        f"has(object.metadata.annotations) && object.metadata.annotations[{_q(DECISION_ANNOTATION)}] == params.metadata.name",
        f"has(object.metadata.annotations) && object.metadata.annotations[{_q(PROFILE_HASH_ANNOTATION)}] == params.data['profile_sha256']",
        f"has(object.metadata.labels) && object.metadata.labels[{_q(PROFILE_LABEL)}] != params.data['profile']",
    ))
    lab.create({"apiVersion": API, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POD_POLICY},
                "spec": {"failurePolicy": "Fail", "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
                         "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                                    "operations": ["CREATE"], "resources": ["pods"],
                                                                    "scope": "Namespaced"}]},
                         "matchConditions": [{"name": "two-fixture-profiles-only",
                                               "expression": f"has(object.metadata.labels) && object.metadata.labels[{_q(PROFILE_LABEL)}] in [{_q(DEFERRED_PROFILE)}, {_q(BASELINE_PROFILE)}]"}],
                         "validations": [{"expression": expression, "message": PROFILE_DENIAL}]}})
    lab.create({"apiVersion": API, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POD_BINDING},
                "spec": {"policyName": POD_POLICY, "validationActions": ["Deny"],
                         "paramRef": {"name": DECISION, "namespace": NAMESPACE, "parameterNotFoundAction": "Deny"},
                         "matchResources": {"namespaceSelector": {"matchLabels": {
                             "kubernetes.io/metadata.name": NAMESPACE}}}}})


def _profile(pod):
    statuses = pod.get("status", {}).get("containerStatuses", [])
    image_ids = [item.get("imageID", "") for item in statuses if item.get("name") == "fixture"]
    image_id, = image_ids
    return {
        "runtime_class": pod.get("spec", {}).get("runtimeClassName", ""),
        "overhead": pod.get("spec", {}).get("overhead", {}),
        "container": next(item for item in pod["spec"]["containers"] if item["name"] == "fixture"),
        "image_id": image_id,
        "pod_uid": pod.get("metadata", {}).get("uid", ""),
    }


def _pod_candidate(workload_fn, name, profile, profile_hash):
    obj = workload_fn(name, "fixture-reviewed-runtime" if profile == DEFERRED_PROFILE else None)
    obj["metadata"].setdefault("labels", {})[PROFILE_LABEL] = profile
    obj["metadata"].setdefault("annotations", {})[DECISION_ANNOTATION] = DECISION
    obj["metadata"]["annotations"][PROFILE_HASH_ANNOTATION] = profile_hash
    return obj


def run(lab, workload_fn, baseline_output, overhead_profile_output, image_ref):
    run_pod = json.loads(lab.kubectl("get", "pod", "fixture-with-overhead", "-o", "json").stdout)
    runtime_class = json.loads(lab.kubectl("get", "runtimeclass", RUNTIME, "-o", "json").stdout)
    run_output = lab.kubectl("logs", "fixture-with-overhead").stdout.strip()
    profile = _profile(run_pod)
    expected_result = hashlib.sha256(b"fixture-readiness-work").hexdigest()
    baseline_hash = hashlib.sha256(baseline_output.encode()).hexdigest()
    observed_hash = hashlib.sha256(run_output.encode()).hexdigest()
    profile_record = {
        "profile": DEFERRED_PROFILE,
        "runtime_class": profile["runtime_class"],
        "overhead": profile["overhead"],
        "container": profile["container"],
        "image_id": profile["image_id"],
        "run_pod_uid": profile["pod_uid"],
        "run_result_sha256": observed_hash,
    }
    profile_hash = hashlib.sha256(json.dumps(profile_record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    scope_valid = (run_pod.get("status", {}).get("phase") == "Succeeded" and bool(profile["pod_uid"])
                   and bool(profile["image_id"]) and profile["runtime_class"] == RUNTIME
                   and profile["container"].get("image") == image_ref and "@sha256:" in profile["image_id"]
                   and runtime_class.get("handler") == "runc"
                   and runtime_class.get("overhead", {}).get("podFixed") == {"cpu": "60m", "memory": "8Mi"}
                   and profile["overhead"] == {"cpu": "60m", "memory": "8Mi"}
                   and run_output == overhead_profile_output == expected_result
                   and baseline_output == expected_result)
    if not scope_valid:
        lab.block("Qualification deferral could not bind to the exact completed fixture run")

    expected_data = {
        "decision": "defer", "profile": DEFERRED_PROFILE, "profile_sha256": profile_hash,
        "run_pod_uid": profile["pod_uid"], "run_image_id_sha256": hashlib.sha256(profile["image_id"].encode()).hexdigest(),
        "run_result_sha256": observed_hash, "baseline_result_sha256": baseline_hash,
        "runtime_class": profile["runtime_class"], "runtime_handler": runtime_class["handler"],
        "protected_measurement": "unavailable",
        "approver": REVIEWER, "compensating_control": COMPENSATING,
        "reassessment_criteria": REASSESS,
        "scope": "synthetic qualification record; protected runtime and hardware evidence unavailable",
    }
    if expected_data["protected_measurement"] != "unavailable":
        lab.block("The fixture must explicitly preserve the unavailable protected measurement")

    _role(lab)
    _decision_policy(lab, expected_data, profile_hash)
    _policy_ready(lab, DECISION_POLICY)
    valid_record = {"apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {"name": DECISION, "annotations": {"fixture.example/profile-sha256": profile_hash}},
                    "immutable": True, "data": expected_data}
    incomplete = dict(valid_record)
    incomplete["data"] = {key: value for key, value in expected_data.items() if key != "reassessment_criteria"}
    incomplete["metadata"] = {"name": DECISION}
    reviewer_missing = _wait_for_policy_decision(lab, REVIEWER, incomplete, DECISION_POLICY, RECORD_DENIAL)
    adoption_unavailable = dict(valid_record)
    adoption_unavailable["data"] = dict(expected_data, decision="adopt")
    adoption_attempt = _submit(lab, REVIEWER, adoption_unavailable)
    observer_attempt = _submit(lab, OBSERVER, valid_record)
    invalid_denials = (_denied(reviewer_missing, DECISION_POLICY, RECORD_DENIAL)
                       and _denied(adoption_attempt, DECISION_POLICY, RECORD_DENIAL)
                       and _denied(observer_attempt, DECISION_POLICY, RECORD_DENIAL))
    created = _submit(lab, REVIEWER, valid_record, dry_run=False)
    if created.returncode:
        lab.block("The scoped reviewer could not create the complete deferral record")
    stored = json.loads(lab.kubectl("get", "configmap", DECISION, "-o", "json").stdout)
    record_bound = (stored.get("immutable") is True and bool(stored.get("metadata", {}).get("uid"))
                    and stored["metadata"].get("namespace") == NAMESPACE
                    and stored["data"] == expected_data
                    and stored["metadata"].get("annotations", {}).get("fixture.example/profile-sha256") == profile_hash)
    _pod_policy(lab)
    _policy_ready(lab, POD_POLICY)
    deferred = _pod_candidate(workload_fn, "fixture-deferred-profile", DEFERRED_PROFILE, profile_hash)
    baseline = _pod_candidate(workload_fn, "fixture-baseline-comparator", BASELINE_PROFILE, profile_hash)
    blocked = _wait_for_policy_decision(lab, REVIEWER, deferred, POD_POLICY, PROFILE_DENIAL)
    baseline_allowed = _submit(lab, REVIEWER, baseline)
    deferred_denied = _denied(blocked, POD_POLICY, PROFILE_DENIAL)
    baseline_permitted = baseline_allowed.returncode == 0
    passed = (scope_valid and invalid_denials and record_bound and deferred_denied and baseline_permitted)
    (lab.evidence / "qualification-deferral-observations.json").write_text(json.dumps({
        "decision_uid": stored["metadata"]["uid"], "decision_name": DECISION,
        "profile_sha256": profile_hash, "runtime_class": profile["runtime_class"],
        "pod_uid": profile["pod_uid"], "image_id_sha256": expected_data["run_image_id_sha256"],
        "runtime_handler": runtime_class["handler"],
        "observed_run_result_sha256": observed_hash, "baseline_result_sha256": baseline_hash,
        "protected_measurement": "unavailable", "compensating_control": COMPENSATING,
        "reassessment_criteria": REASSESS, "run_and_profile_bound": scope_valid,
        "incomplete_adoption_or_wrong_reviewer_denied": invalid_denials,
        "immutable_deferral_record_bound": record_bound, "exact_deferred_profile_denied": deferred_denied,
        "baseline_comparator_admitted": baseline_permitted,
        "tee_or_device_attestation_tested": False,
    }, indent=2) + "\n")
    lab.check("qualification", "An authorized evidence-bound deferral persists its safeguards and blocks only that exact fixture profile",
              passed, {"run_and_profile_bound": scope_valid, "incomplete_adoption_or_wrong_reviewer_denied": invalid_denials,
                       "immutable_deferral_record_bound": record_bound, "exact_deferred_profile_denied": deferred_denied,
                       "baseline_comparator_admitted": baseline_permitted})
