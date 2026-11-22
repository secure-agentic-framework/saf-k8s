"""Verify StorageClass API boundaries and a scoped approved-backend rule."""
import json
import time

APPROVED = "saf-fixture-approved-backend"
UNAPPROVED = "saf-fixture-unapproved-backend"
POLICY = "saf-0701-003-approved-storage"
SCOPE = (
    "Kubernetes v1.36.1 kind. Strict server validation checks the StorageClass API. "
    "A scoped admission policy requires the exact approved StorageClass for fixture "
    "claims. This is a declaration boundary. The separate guest fixture verifies "
    "actual file-backed LUKS encryption for a Kubernetes PV. Cloud providers, "
    "approved-class authority, production coverage and KMS rotation require "
    "their own evidence."
)


def storage_class(name):
    return {"kind": "StorageClass", "apiVersion": "storage.k8s.io/v1", "metadata": {"name": name},
            "provisioner": "kubernetes.io/no-provisioner", "volumeBindingMode": "WaitForFirstConsumer"}


def claim(name, class_name):
    return {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": name},
            "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": class_name,
                     "resources": {"requests": {"storage": "1Mi"}}}}


def dry_run(lab, manifest):
    return lab.kubectl("create", "-f", "-", "--dry-run=server", "--validate=strict",
                       "-o", "json", payload=json.dumps(manifest), allow_failure=True)


def policy(lab):
    version = "admissionregistration.k8s.io/v1"
    lab.kubectl("label", "namespace", "saf-test", "saf-k8s.example/approved-backend=required")
    lab.create({"apiVersion": version, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail", "matchConstraints": {"resourceRules": [{
                    "apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"],
                    "resources": ["persistentvolumeclaims"],
                }]}, "validations": [{
                    "expression": f"has(object.spec.storageClassName) && object.spec.storageClassName == '{APPROVED}'",
                    "message": "fixture claim requires the exact approved backend class", "reason": "Forbidden",
                }]}})
    lab.create({"apiVersion": version, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"], "matchResources": {
                    "namespaceSelector": {"matchLabels": {"saf-k8s.example/approved-backend": "required"}},
                }}})


def run(lab):
    invalid_setting = storage_class("saf-storageclass-generic-setting")
    invalid_setting["encryptionConfiguration"] = {"enabled": True}
    invalid = dry_run(lab, invalid_setting)
    rejected = invalid.returncode != 0 and 'unknown field "encryptionConfiguration"' in invalid.stderr
    lab.check("positive", "The StorageClass API rejects the alleged portable encryptionConfiguration field",
              rejected, {"strict_schema_rejected_unknown_field": rejected})
    lab.create(storage_class(APPROVED))
    lab.create(storage_class(UNAPPROVED))

    unsafe = claim("unapproved-fixture-claim", UNAPPROVED)
    before = dry_run(lab, unsafe)
    lab.check("red", "The same unapproved class declaration passes before the allowlist policy",
              before.returncode == 0, {"unapproved_claim_admitted": before.returncode == 0})
    policy(lab)
    deadline = time.monotonic() + 20
    while True:
        after = dry_run(lab, unsafe)
        denied = (after.returncode != 0 and "(Forbidden)" in after.stderr
                  and f"ValidatingAdmissionPolicy '{POLICY}'" in after.stderr
                  and "fixture claim requires the exact approved backend class" in after.stderr)
        if denied or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check("green", "The allowlist rejects the same unapproved backend declaration",
              denied, {"denied_by_expected_policy": denied})
    permitted = dry_run(lab, claim("approved-fixture-claim", APPROVED))
    actual = json.loads(permitted.stdout)["spec"]["storageClassName"] if permitted.returncode == 0 else None
    lab.check("positive", "The exact approved backend class declaration remains admissible",
              actual == APPROVED, {"approved_class_admitted": actual == APPROVED})
