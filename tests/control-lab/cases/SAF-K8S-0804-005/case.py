"""Verify narrowly scoped Kubernetes access to an inert release marker."""

import json
import time

SCOPE = "Actual Kubernetes RBAC release and revocation for an inert public marker, plus software-only signed synthetic verifier-result checks and recipient-bound ciphertext release; no TEE, provider KMS, or production key-release claim."
NS = "saf-test"
RBAC = "rbac.authorization.k8s.io"
TARGET = "fixture-release-marker"
OTHER = "fixture-unrelated-marker"
ROLE = "fixture-scoped-release"
WORKLOAD = "fixture-approved-consumer"
UNRELATED = "fixture-other-consumer"


def principal(name):
    return f"system:serviceaccount:{NS}:{name}"


def allowed(lab, name, resource):
    response = lab.create({"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview",
                           "spec": {"user": principal(name), "resourceAttributes": {
                               "namespace": NS, "verb": "get", "resource": "configmaps", "name": resource}}})["status"]
    if response.get("evaluationError"):
        lab.block("The release authorization review could not evaluate the fixture subject")
    return response.get("allowed", False)


def see_decision(lab, name, resource, expected):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        decision = allowed(lab, name, resource)
        if decision == expected:
            return decision
        time.sleep(0.4)
    lab.block("The real API did not converge to the expected release authorization")


def bind(lab, review):
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "RoleBinding",
                "metadata": {"name": ROLE, "annotations": {"fixture.example/review": review}},
                "roleRef": {"apiGroup": RBAC, "kind": "Role", "name": ROLE},
                "subjects": [{"kind": "ServiceAccount", "namespace": NS, "name": WORKLOAD}]})


def grant(lab, receipt, now):
    if (receipt["appraisal"] != "fixture-approved" or receipt["subject"] != WORKLOAD
            or receipt["resource"] != TARGET or not receipt["valid_after"] <= now < receipt["expires"]):
        return False
    bind(lab, receipt["review"])
    return True

def run(lab):
    for name in (WORKLOAD, UNRELATED):
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": name},
                    "automountServiceAccountToken": False})
    for name in (TARGET, OTHER):
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                    "data": {"marker": name + "-public"}})
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "Role", "metadata": {"name": ROLE},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                           "resourceNames": [TARGET], "verbs": ["get"]}]})
    bind(lab, "fixture-unconditional-counterfactual")
    broad = see_decision(lab, WORKLOAD, TARGET, True)
    lab.kubectl("delete", "rolebinding", ROLE)
    see_decision(lab, WORKLOAD, TARGET, False)
    receipt = {"subject": WORKLOAD, "resource": TARGET, "appraisal": "fixture-approved",
               "valid_after": 10, "expires": 20, "review": "fixture-attestation-review"}
    stale_provisioned = grant(lab, receipt, now=20)
    other_provisioned = grant(lab, dict(receipt, subject=UNRELATED), now=14)
    incorrect_resource_provisioned = grant(lab, dict(receipt, resource=OTHER), now=14)
    still_denied = not allowed(lab, WORKLOAD, TARGET)
    lab.check("red", "An unconditional grant exposes the marker while expired or mismatched results leave it unavailable",
              broad and not stale_provisioned and not other_provisioned and not incorrect_resource_provisioned and still_denied,
              {"marker_initially_available_without_review": broad, "expired_receipt_denied": not stale_provisioned, "different_subject_denied": not other_provisioned,
               "different_resource_denied": not incorrect_resource_provisioned, "target_inaccessible": still_denied})

    granted = grant(lab, receipt, now=14)
    permitted = see_decision(lab, WORKLOAD, TARGET, True)
    result = lab.kubectl("--as", principal(WORKLOAD), "get", "configmap", TARGET, "-o", "json")
    received = json.loads(result.stdout)["data"]["marker"] == TARGET + "-public"
    narrow = not allowed(lab, WORKLOAD, OTHER) and not allowed(lab, UNRELATED, TARGET)
    lab.check("green", "The matching modeled result permits only the intended actual Kubernetes read",
              granted and permitted and received and narrow, {"released_public_marker": received, "unrelated_reads_denied": narrow})

    lab.kubectl("delete", "rolebinding", ROLE)
    after = not see_decision(lab, WORKLOAD, TARGET, False)
    lab.check("positive", "Revocation removes permission for future checkout of the same public marker",
              after, {"later_read_denied": after})
    (lab.evidence / "sensitive-release-observations.json").write_text(json.dumps({
        "modeled_attestation": True, "prior_target_unavailable": still_denied, "public_marker_released": received,
        "unrelated_reads_denied": narrow, "later_read_denied": after, "real_key_release_tested": False}, indent=2) + "\n")

    # Additive software-only recipient binding witness; original checks above are unchanged.
    import importlib.util as _importlib_util
    from pathlib import Path as _Path
    _recipient_spec = _importlib_util.spec_from_file_location(
        "recipient_release", _Path(__file__).with_name("recipient_release.py"))
    _recipient_release = _importlib_util.module_from_spec(_recipient_spec)
    _recipient_spec.loader.exec_module(_recipient_release)
    _recipient_release.run(lab)

    _signed_spec = _importlib_util.spec_from_file_location(
        "saf_0804_005_signed_release", _Path(__file__).with_name("signed_release.py"))
    if _signed_spec is None or _signed_spec.loader is None:
        lab.block("Could not load the bounded signed-result release witness")
    _signed_release = _importlib_util.module_from_spec(_signed_spec)
    _signed_spec.loader.exec_module(_signed_release)
    _signed_release.run(lab)
