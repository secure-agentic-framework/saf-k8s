"""Verify an inert signature and enforce a modeled host-evidence decision in Kubernetes."""

import hashlib
import json
from pathlib import Path
import time

SCOPE = "Real signature checks over inert fixture bytes and Kubernetes admission over modeled kernel and boot evidence."
ROOT = Path(__file__).parent
CONFIG = "fixture-module-review"
POLICY = "fixture-approved-module-review"
POD = "fixture-reviewed-accelerator"
SUBMITTER = "fixture-module-workload-submitter"
SUBMITTER_READ_ROLE = "fixture-module-review-submit-read"
SUBMITTER_READ_BINDING = "fixture-module-review-submit-read"
SIGNER_DENIAL = "Fixture signature is unapproved"
MODE_DENIAL = "Fixture module enforcement is unverified"
BOOT_DENIAL = "Fixture boot evidence is unverified"
DIGEST_DENIAL = "Fixture digest does not match the review"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"


def signature(lab, signer, signed_by, marker):
    result = lab.command("openssl", "dgst", "-sha256", "-verify", str(ROOT / f"{signer}-public.pem"),
                         "-signature", str(ROOT / f"{signed_by}-signature.der"), str(marker), allow_failure=True)
    return result.returncode == 0 and "Verified OK" in result.stdout


def workload(digest):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": POD,
            "annotations": {"fixture.example/reviewed-digest": digest}},
            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "fixture", "image": IMAGE, "command": ["python", "-c", "import time; time.sleep(130)"],
                                     "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                                                   "limits": {"cpu": "100m", "memory": "40Mi"}},
                                     "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}}}]}}


def install(lab):
    api = "admissionregistration.k8s.io/v1"
    checks = {
        SIGNER_DENIAL: "params != null && params.data['signature'] == 'trusted'",
        MODE_DENIAL: "params != null && params.data['module-policy'] == 'enforced'",
        BOOT_DENIAL: "params != null && params.data['boot-review'] == 'verified'",
        DIGEST_DENIAL: "params != null && has(object.metadata.annotations) && "
                       "object.metadata.annotations['fixture.example/reviewed-digest'] == params.data['digest']",
    }
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail", "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
                         "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                                "operations": ["CREATE"], "resources": ["pods"]}]},
                         "validations": [{"expression": expression, "message": message} for message, expression in checks.items()]}})
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"],
                         "paramRef": {"name": CONFIG, "namespace": "saf-test", "parameterNotFoundAction": "Deny"},
                         "matchResources": {"namespaceSelector": {"matchLabels": {"fixture.example/module-policy": "true"}}}}})


def update(lab, fields):
    patch = [{"op": "replace", "path": "/data", "value": fields}]
    lab.kubectl("patch", "configmap", CONFIG, "--type=json", "-p", json.dumps(patch))


def observe(lab, manifest, *, denial=None):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        out = lab.create(manifest, dry_run=True, allow_failure=True)
        if denial and out.returncode and denial in out.stderr:
            return True
        if denial is None and out.returncode == 0:
            return True
        time.sleep(0.4)
    lab.block("The modeled review did not produce the expected admission decision")


def run(lab):
    marker = ROOT / "module-marker.txt"
    digest = hashlib.sha256(marker.read_bytes()).hexdigest()
    modified_marker = lab.kubeconfig.parent / "changed-marker.txt"
    modified_marker.write_bytes(marker.read_bytes() + b"owned fixture change\n")
    self_valid = signature(lab, "alternate", "alternate", marker)
    trusted = signature(lab, "approved", "approved", marker)
    alternate_not_trusted = not signature(lab, "approved", "alternate", marker)
    changed_not_trusted = not signature(lab, "approved", "approved", modified_marker)
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted",
                "fixture.example/module-policy=true")
    fields = {"signature": "unapproved", "module-policy": "enforced", "boot-review": "verified", "digest": digest}
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CONFIG}, "data": fields})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": SUBMITTER_READ_ROLE},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [CONFIG],
                           "verbs": ["get"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": SUBMITTER_READ_BINDING},
                "subjects": [{"kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": SUBMITTER}],
                "roleRef": {"kind": "Role", "apiGroup": "rbac.authorization.k8s.io",
                            "name": SUBMITTER_READ_ROLE}})
    pod = workload(digest)
    baseline = observe(lab, pod)
    lab.check("red", "A cryptographically valid alternate signature and claimed boot state alone leave the fixture admissible",
              self_valid and baseline, {"alternate_signature_self_valid": self_valid, "admitted_without_policy": baseline})

    install(lab)
    unapproved = observe(lab, pod, denial=SIGNER_DENIAL)
    enforced = {**fields, "signature": "trusted" if trusted else "unapproved"}
    update(lab, {**enforced, "module-policy": "permissive"})
    permissive = observe(lab, pod, denial=MODE_DENIAL)
    update(lab, {**enforced, "boot-review": "unknown"})
    boot_unknown = observe(lab, pod, denial=BOOT_DENIAL)
    lab.check("green", "The live policy requires approved signature, restrictive modeled policy and independent boot evidence",
              unapproved and permissive and boot_unknown and alternate_not_trusted and changed_not_trusted,
              {"unapproved_signature_denied": unapproved, "permissive_policy_denied": permissive,
               "missing_boot_evidence_denied": boot_unknown, "alternate_signer_rejected": alternate_not_trusted,
               "changed_bytes_rejected": changed_not_trusted})

    update(lab, enforced)
    before_parameter = json.loads(lab.kubectl("get", "configmap", CONFIG, "-o", "json").stdout)
    before_uid = before_parameter["metadata"]["uid"]
    before_data = before_parameter["data"]
    submitted_read = json.loads(lab.kubectl("--as", SUBMITTER, "get", "configmap", CONFIG, "-o", "json").stdout)
    can_read_parameter = (submitted_read["metadata"]["uid"] == before_uid
                          and submitted_read["data"] == before_data)
    if not can_read_parameter:
        lab.block("The fixture submitter's exact parameter read differs from the independent API read")
    submitter_patch = lab.kubectl("--as", SUBMITTER, "patch", "configmap", CONFIG, "--type=merge",
                                  "-p", json.dumps({"data": {"signature": "fixture-forged-trusted"}}),
                                  allow_failure=True)
    denial = submitter_patch.stderr.lower()
    status_denied_patch = (submitter_patch.returncode != 0 and "error from server (forbidden)" in denial and
                           f'configmaps "{CONFIG}" is forbidden' in denial and
                           f'user "{SUBMITTER.lower()}" cannot patch resource "configmaps"' in denial and
                           'namespace "saf-test"' in denial)
    after_parameter = json.loads(lab.kubectl("get", "configmap", CONFIG, "-o", "json").stdout)
    unchanged_parameter = (after_parameter["metadata"]["uid"] == before_uid and
                           after_parameter["data"] == before_data)
    lab.check("evidence_record_write_rejected", "The fixture submitter can read but cannot patch the exact module-evidence parameter",
              can_read_parameter and status_denied_patch and unchanged_parameter,
              {"exact_parameter_get_allowed": can_read_parameter,
               "api_status_forbids_patch": status_denied_patch,
               "parameter_uid_and_data_unchanged": unchanged_parameter})
    approved = observe(lab, pod)
    altered_digest = hashlib.sha256(modified_marker.read_bytes()).hexdigest()
    wrong_digest = observe(lab, workload(altered_digest), denial=DIGEST_DENIAL)
    lab.create(pod)
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{POD}", "--timeout=55s", timeout=65)
    lab.check("positive", "A Pod runs only once the trusted fixture record applies to its exact digest",
              trusted and approved and wrong_digest,
              {"trusted_signature": trusted, "mismatched_digest_denied": wrong_digest, "fixture_ready": True})
    (lab.evidence / "module-trust-observations.json").write_text(json.dumps({
        "fixture_signature_verified": trusted, "unapproved_signature_denied": unapproved,
        "permissive_policy_denied": permissive, "missing_boot_evidence_denied": boot_unknown,
        "mismatched_digest_denied": wrong_digest, "fixture_ready": True,
        "submitter_get_allowed": can_read_parameter, "submitter_patch_denied": status_denied_patch,
        "parameter_uid_and_data_unchanged": unchanged_parameter,
        "parameter_readback": {"uid_before": before_uid, "uid_after": after_parameter["metadata"]["uid"],
                               "data_before": before_data, "data_after": after_parameter["data"]},
        "host_evidence_is_synthetic": True}, indent=2) + "\n")
