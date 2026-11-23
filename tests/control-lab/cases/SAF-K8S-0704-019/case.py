"""Enforce the intended service-account selection for two isolated workload fixtures."""

import json
import time

SCOPE = "Live Kubernetes admission and Pod API state for distinct fixture ServiceAccounts and an explicitly projected audience."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
POLICY = "fixture-workload-identities"
REASON = "Fixture workload must use its approved ServiceAccount"
WORKLOADS = {"fixture-workload-a": "fixture-identity-a", "fixture-workload-b": "fixture-identity-b"}
AUDIENCE = "saf-fixture-external"


def pod(name, subject):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
            "spec": {"restartPolicy": "Never", "serviceAccountName": subject, "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                     "volumes": [{"name": "fixture-projection", "projected": {"sources": [{"serviceAccountToken":
                         {"path": "token", "audience": AUDIENCE, "expirationSeconds": 600}}]}}],
                     "containers": [{"name": "inert", "image": IMAGE, "command": ["python", "-c", "import time; time.sleep(180)"],
                                     "resources": {"requests": {"cpu": "5m", "memory": "12Mi"}, "limits": {"cpu": "100m", "memory": "40Mi"}},
                                     "volumeMounts": [{"name": "fixture-projection", "mountPath": "/identity", "readOnly": True}],
                                     "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}}}]}}


def install(lab):
    api = "admissionregistration.k8s.io/v1"
    choices = [f"(object.metadata.name == '{name}' && object.spec.serviceAccountName == '{subject}')"
               for name, subject in WORKLOADS.items()]
    predicate = " || ".join(choices)
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail",
                         "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                                "operations": ["CREATE"], "resources": ["pods"]}]},
                         "validations": [{"expression": predicate, "message": REASON}]}})
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"], "matchResources": {
                    "namespaceSelector": {"matchLabels": {"fixture.example/workload-identities": "true"}}}}})


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted",
                "fixture.example/workload-identities=true")
    for subject in WORKLOADS.values():
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": subject},
                    "automountServiceAccountToken": False})
    first, second = WORKLOADS
    incorrect = pod(first, WORKLOADS[second])
    admitted = lab.create(incorrect, dry_run=True)["spec"]["serviceAccountName"] == WORKLOADS[second]
    lab.check("red", "With no workload mapping rule, Kubernetes accepts the other fixture ServiceAccount",
              admitted, {"incorrect_subject_admitted": admitted})

    install(lab)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        denied = lab.create(incorrect, dry_run=True, allow_failure=True)
        if denied.returncode and REASON in denied.stderr:
            break
        time.sleep(0.45)
    else:
        lab.block("The fixture ServiceAccount mapping policy did not return the expected explicit denial")
    missing = lab.create(pod(second, "default"), dry_run=True, allow_failure=True)
    rejects_default = missing.returncode != 0 and REASON in missing.stderr
    lab.check("green", "Admission denies the other workload's ServiceAccount and a default-account declaration",
              rejects_default, {"incorrect_subject_denied": True, "default_subject_denied": rejects_default})

    approved = {}
    for name, subject in WORKLOADS.items():
        lab.create(pod(name, subject))
    for name, subject in WORKLOADS.items():
        lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=55s", timeout=65)
        spec = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)["spec"]
        approved[name] = (spec["serviceAccountName"] == subject
                          and spec["automountServiceAccountToken"] is False
                          and len(spec["volumes"]) == 1
                          and spec["volumes"][0]["projected"]["sources"][0]["serviceAccountToken"]["audience"] == AUDIENCE)
    lab.check("positive", "Both approved Pods run with different expected ServiceAccounts and the declared projection",
              all(approved.values()), {"approved_workload_specs": approved})
    (lab.evidence / "identity-binding-observations.json").write_text(json.dumps(
        {"incorrect_subject_before_policy": admitted, "incorrect_subject_denied": True,
         "default_subject_denied": rejects_default, "approved_workload_specs": approved,
         "provider_federation_tested": False}, indent=2) + "\n")
