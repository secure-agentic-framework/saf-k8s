"""Enforce an inert release record at a real Kubernetes admission boundary."""

import hashlib
import json
import time

SCOPE = "A Kubernetes promotion boundary with fictional check records for one public fixture artifact."
NAME = "saf-fixture-release"
PARAM = "saf-release-expectations"
CHECKS = ("source-analysis", "component-analysis", "ci-secret-detection", "artifact-check")
ARTIFACT = b"public release candidate saf-k8s-0606-011\n"
EXPECTED = {"artifact-digest": "sha256:" + hashlib.sha256(ARTIFACT).hexdigest(),
            "source-revision": "fixture-source-v1", "test-revision": "fixture-checks-v1",
            "policy-revision": "fixture-promotion-v1"}


def request(name, fields, *, labels=True):
    metadata = {"name": name}
    if labels:
        metadata["labels"] = {"saf.example/release-request": "true"}
    return {"apiVersion": "v1", "kind": "ConfigMap", "metadata": metadata,
            "immutable": True, "data": fields}


def install_gate(lab):
    lab.create(request(PARAM, EXPECTED, labels=False))
    scope = {"objectSelector": {"matchLabels": {"saf.example/release-request": "true"}},
             "resourceRules": [{"operations": ["CREATE"], "apiGroups": [""], "apiVersions": ["v1"],
                                "resources": ["configmaps"], "scope": "Namespaced"}]}
    field_match = " && ".join(
        f"'{field}' in object.data && object.data['{field}'] == params.data['{field}']"
        for field in EXPECTED
    )
    checks = " && ".join(f"'{name}' in object.data && object.data['{name}'] == 'passed'" for name in CHECKS)
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
                "metadata": {"name": NAME},
                "spec": {"failurePolicy": "Fail", "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
                         "matchConstraints": scope,
                         "validations": [
                             {"expression": "has(object.data) && " + field_match,
                              "message": "release candidate or evidence revision mismatch"},
                             {"expression": "has(object.data) && " + checks,
                              "message": "required release check missing or unsuccessful"},
                         ]}})
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
                "metadata": {"name": NAME},
                "spec": {"policyName": NAME, "validationActions": ["Deny"],
                         "paramRef": {"name": PARAM, "namespace": "saf-test",
                                      "parameterNotFoundAction": "Deny"},
                         "matchResources": {"namespaceSelector": {"matchLabels": {
                             "kubernetes.io/metadata.name": "saf-test"}}}}})


def rejection(lab, name, fields, expected):
    result = lab.create(request(name, fields), dry_run=True, allow_failure=True)
    return result.returncode != 0 and NAME in result.stderr and expected in result.stderr


def run(lab):
    clean = {**EXPECTED, **{name: "passed" for name in CHECKS}}
    finding = {**clean, "source-analysis": "failed"}
    permitted = lab.create(request("before-gate", finding), dry_run=True)
    lab.check("red", "Before admission enforcement, a promotion with a failed check can reach the API",
              permitted["data"] == finding, {"unchecked_failed_result_accepted": permitted["data"] == finding})
    install_gate(lab)
    gate_message = "required release check missing or unsuccessful"
    expiry = time.monotonic() + 45
    while time.monotonic() < expiry:
        if rejection(lab, "failed-check", finding, gate_message):
            break
        time.sleep(1)
    else:
        lab.block("The fixture's release admission binding did not enforce the expected denial")
    missing = dict(clean)
    del missing["ci-secret-detection"]
    skipped = {**clean, "artifact-check": "skipped"}
    rejected_states = {"failed": True, "missing": rejection(lab, "missing-check", missing, gate_message),
                       "skipped": rejection(lab, "skipped-check", skipped, gate_message)}
    lab.check("green", "Live admission denies failed, missing, or skipped check records",
              all(rejected_states.values()), rejected_states)
    rejected_bindings = {}
    for field in EXPECTED:
        changed = {**clean, field: "sha256:" + "0" * 64 if field == "artifact-digest" else "different-fixture-v2"}
        rejected_bindings[field] = rejection(lab, f"stale-{field}", changed,
                                             "release candidate or evidence revision mismatch")
    lab.check("green", "Live admission rejects evidence for a different artifact, source, tests or policy",
              all(rejected_bindings.values()), rejected_bindings)
    approved = lab.create(request("approved-release", clean))
    stored = json.loads(lab.kubectl("get", "configmap", "approved-release", "-o", "json").stdout)
    verified = stored["metadata"]["uid"] == approved["metadata"]["uid"] and stored["data"] == clean
    lab.check("positive", "A matching release record with passed checks persists after admission",
              verified and stored["immutable"], {"same_api_object": verified, "artifact": EXPECTED["artifact-digest"]})
    (lab.evidence / "promotion-observations.json").write_text(json.dumps({
        "expected_binding": EXPECTED, "denied_check_states": rejected_states,
        "denied_binding_mismatches": rejected_bindings, "matching_record_stored": verified,
    }, indent=2) + "\n")
