"""Validate synthetic AI base-image evidence and enforce it with Kubernetes admission."""
from hashlib import sha256
import hmac
import json
import time

from fixtures import BUSYBOX_IMAGE, container


IMAGE = BUSYBOX_IMAGE
POLICY = "saf-0601-007-base-image"
BINDING = POLICY
IMAGE_DENIAL = "saf-test Pods must use the exact validated, digest-pinned AI base image"
EVIDENCE_DENIAL = "saf-test Pods must carry the validated base-image evidence and profile"
ANNOTATIONS = {
    "saf.example/base-image-evidence": "saf-fixture-ai-base-v1",
    "saf.example/base-image-evidence-sha256": "",
    "saf.example/gpu-profile": "cuda-12.4-pytorch-2.5",
}
# This key and evidence are test-only fixtures, not organizational credentials.
FIXTURE_KEY = b"SAF-K8S-0601-007 deterministic synthetic signing key v1"
FIXTURE_KEY_ID = "fixture-ai-platform-key-v1"

SCOPE = (
    "Offline synthetic test of one digest-pinned inert CUDA/PyTorch base identity. A locally "
    "HMAC-authenticated synthetic approval record binds that digest to a GPU/framework profile "
    "and curation assertions; a Kubernetes ValidatingAdmissionPolicy then admits only that exact "
    "image and evidence metadata in the runner's saf-test namespace. The approved pinned BusyBox "
    "fixture runs under the configured policy. Negative requests use server-side dry-run. GPU, "
    "driver and framework compatibility, trusted production signers and release coverage remain "
    "unverified deployment scope."
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def signed_record(subject=IMAGE, *, profile="cuda-12.4-pytorch-2.5", curated=True):
    body = {
        "schema": "saf-fixture.ai-base-validation/v1",
        "key_id": FIXTURE_KEY_ID,
        "subject": subject,
        "profile": profile,
        "gpu_compatibility": "fixture-validated",
        "framework_compatibility": "fixture-validated",
        "nonessential_components_removed": curated,
        "exception": None,
    }
    signature = hmac.new(FIXTURE_KEY, canonical(body), "sha256").hexdigest()
    return {"payload": body, "signature": signature}


def verify_record(record, expected_subject=IMAGE):
    body = record.get("payload", {})
    supplied = record.get("signature", "")
    expected = hmac.new(FIXTURE_KEY, canonical(body), "sha256").hexdigest()
    checks = {
        "signature_valid": hmac.compare_digest(supplied, expected),
        "trusted_fixture_key": body.get("key_id") == FIXTURE_KEY_ID,
        "subject_matches_pinned_image": body.get("subject") == expected_subject,
        "profile_matches": body.get("profile") == "cuda-12.4-pytorch-2.5",
        "gpu_compatibility_recorded": body.get("gpu_compatibility") == "fixture-validated",
        "framework_compatibility_recorded": body.get("framework_compatibility") == "fixture-validated",
        "curation_recorded": body.get("nonessential_components_removed") is True,
        "no_exception_used": body.get("exception") is None,
    }
    return checks


def policy_objects(evidence_hash):
    image_check = (
        "object.spec.containers.size() == 1 && "
        f"object.spec.containers[0].image == '{IMAGE}' && "
        "(!has(object.spec.initContainers) || object.spec.initContainers.size() == 0)"
    )
    annotations = {
        "saf.example/base-image-evidence": "saf-fixture-ai-base-v1",
        "saf.example/base-image-evidence-sha256": evidence_hash,
        "saf.example/gpu-profile": "cuda-12.4-pytorch-2.5",
    }
    metadata_check = "has(object.metadata.annotations) && " + " && ".join(
        f"('{key}' in object.metadata.annotations && object.metadata.annotations['{key}'] == '{value}')"
        for key, value in annotations.items()
    )
    policy = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": POLICY},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {"resourceRules": [{
                "apiGroups": [""], "apiVersions": ["v1"],
                "operations": ["CREATE", "UPDATE"], "resources": ["pods"],
            }]},
            "validations": [
                {"expression": image_check, "message": IMAGE_DENIAL},
                {"expression": metadata_check,
                 "message": EVIDENCE_DENIAL},
            ],
        },
    }
    binding = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": BINDING},
        "spec": {
            "policyName": POLICY,
            "validationActions": ["Deny"],
            "matchResources": {"namespaceSelector": {"matchLabels": {
                "kubernetes.io/metadata.name": "saf-test",
            }}},
        },
    }
    return policy, binding


def pod(name, image=IMAGE, annotations=None):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": "saf-test", "annotations": annotations or {}},
        "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False, "containers": [container("fixture", image=image)]},
    }


def server_dry_run(lab, resource):
    result = lab.kubectl("create", "-f", "-", "-o", "json", "--dry-run=server",
                         payload=json.dumps(resource, sort_keys=True), allow_failure=True)
    return {
        "accepted": result.returncode == 0,
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def normalized_observation(raw):
    # Strip API-server wording, request IDs and version-specific error formatting.
    return {"accepted": raw["accepted"], "rejected": not raw["accepted"]}


def write_evidence(lab, raw, normalized):
    (lab.evidence / "base-image-admission-raw.json").write_text(
        json.dumps(raw, indent=2, sort_keys=True) + "\n")
    (lab.evidence / "base-image-admission-normalized.json").write_text(
        json.dumps(normalized, indent=2, sort_keys=True) + "\n")


def run(lab):
    approved = signed_record()
    valid_checks = verify_record(approved)
    if not all(valid_checks.values()):
        lab.block("The deterministic synthetic base-image evidence did not verify")
    evidence_hash = sha256(canonical(approved)).hexdigest()
    annotations = {**ANNOTATIONS, "saf.example/base-image-evidence-sha256": evidence_hash}

    bad_subject = signed_record(subject="fixture.invalid/unreviewed-base:latest")
    bad_profile = signed_record(profile="cuda-11.8-pytorch-2.1")
    bad_curation = signed_record(curated=False)
    tampered = json.loads(json.dumps(approved))
    tampered["payload"]["nonessential_components_removed"] = False
    evidence_cases = {
        "wrong-subject": verify_record(bad_subject),
        "wrong-profile": verify_record(bad_profile),
        "not-curated": verify_record(bad_curation),
        "tampered-signature": verify_record(tampered),
    }
    evidence_rejected = all(not all(checks.values()) for checks in evidence_cases.values())

    # Demonstrate the exact same request is admitted before the reviewed policy exists.
    baseline_request = pod("saf-007-generic", "fixture.invalid/unreviewed-base:latest", annotations)
    baseline = server_dry_run(lab, baseline_request)
    lab.check("red", "Without the base-image admission gate, the unapproved input is admitted",
              baseline["accepted"], normalized_observation(baseline))

    policy, binding = policy_objects(evidence_hash)
    applied = lab.kubectl("apply", "-f", "-", payload=json.dumps({"apiVersion": "v1", "kind": "List",
        "items": [policy, binding]}, sort_keys=True))
    installed = lab.kubectl("get", "validatingadmissionpolicy", POLICY, "-o", "json")
    installed_obj = json.loads(installed.stdout)
    policy_installed = installed_obj.get("metadata", {}).get("name") == POLICY

    cases = {
        "unpinned-generic-image": baseline_request,
        "wrong-image-digest": pod("saf-007-wrong-digest", IMAGE[:-64] + "b" * 64, annotations),
        "missing-evidence": pod("saf-007-missing-evidence", annotations={}),
        "wrong-evidence-digest": pod("saf-007-wrong-evidence", annotations={
            **annotations, "saf.example/base-image-evidence-sha256": "0" * 64}),
        "wrong-profile-annotation": pod("saf-007-wrong-profile", annotations={
            **annotations, "saf.example/gpu-profile": "cuda-11.8-pytorch-2.1"}),
    }
    deadline = time.monotonic() + 25
    while True:
        activation = server_dry_run(lab, baseline_request)
        if IMAGE_DENIAL in activation["stderr"] or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    denied = {name: server_dry_run(lab, resource) for name, resource in cases.items()}
    matched = {name: not result["accepted"] and (IMAGE_DENIAL if name in {
        "unpinned-generic-image", "wrong-image-digest"} else EVIDENCE_DENIAL) in result["stderr"]
        for name, result in denied.items()}
    green = policy_installed and evidence_rejected and all(matched.values())
    lab.check("green", "Admission denies unpinned, mismatched, or unsupported base-image proposals",
              green, {"policy_installed": policy_installed, "synthetic_evidence_rejected": evidence_rejected,
                      "denied": {name: normalized_observation(result) for name, result in denied.items()}})

    created = lab.create(pod("saf-007-approved", annotations=annotations))
    lab.kubectl("wait", "--for=condition=Ready", "pod/saf-007-approved", "--timeout=95s", timeout=105)
    live = json.loads(lab.kubectl("get", "pod", "saf-007-approved", "-o", "json").stdout)
    runtime = live["status"]["containerStatuses"][0]
    positive = (live["metadata"]["uid"] == created["metadata"]["uid"] and
                live["spec"]["containers"][0]["image"] == IMAGE and
                runtime["ready"] and bool(runtime["imageID"]) and
                all(live["metadata"]["annotations"].get(k) == v for k, v in annotations.items()))
    lab.check("positive", "The exact reviewed base-image identity is admitted and the fixture runs",
              positive, {"admitted_and_running": positive})

    raw = {
        "control_id": "SAF-K8S-0601-007",
        "pinned_image": IMAGE,
        "fixture_key_id": FIXTURE_KEY_ID,
        "synthetic_approval_record": approved,
        "synthetic_record_sha256": evidence_hash,
        "synthetic_evidence_checks": valid_checks,
        "negative_synthetic_evidence_checks": evidence_cases,
        "policy_apply_stdout": applied.stdout,
        "policy_installed": policy_installed,
        "policy": policy,
        "binding": binding,
        "baseline": baseline,
        "denied_proposals": denied,
        "approved_proposal": {"pod_uid": live["metadata"]["uid"], "runtime_image_id": runtime["imageID"]},
        "cluster_uid": lab.kubectl("get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}").stdout,
    }
    normalized = {
        "control_id": "SAF-K8S-0601-007",
        "pinned_image": IMAGE,
        "synthetic_evidence": {"signature_valid": all(valid_checks.values()),
                               "negative_cases_rejected": evidence_rejected},
        "admission": {
            "policy_installed": policy_installed,
            "baseline_without_gate_admitted": baseline["accepted"],
            "negative_proposals_denied": matched,
            "approved_proposal_admitted": positive,
        },
    }
    write_evidence(lab, raw, normalized)
