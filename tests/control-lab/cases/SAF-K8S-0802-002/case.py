"""Enforce the reviewed workload runtime and pinned image in a disposable cluster."""

import json
import time

SCOPE = "Actual Kubernetes RuntimeClass and image-reference admission for a CPU-only fixture with no NVIDIA runtime."
APPROVED = "fixture-reviewed-runtime"
ALTERNATE = "fixture-unreviewed-runtime"
NAME = "fixture-reviewed-image"
POLICY = "fixture-runtime-and-image"
DENIAL = "Workload must use the fixture-approved runtime and image"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"


def workload(runtime, image):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": NAME},
            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False, "runtimeClassName": runtime,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "fixture", "image": image, "command": ["python", "-u", "-c",
                                     "import time; print('reviewed-runtime-marker'); time.sleep(120)"],
                                     "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                                                   "limits": {"cpu": "100m", "memory": "40Mi"}},
                                     "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}}}]}}


def policy(lab):
    api = "admissionregistration.k8s.io/v1"
    containers = "object.spec.containers + (has(object.spec.initContainers) ? object.spec.initContainers : [])"
    predicate = f"has(object.spec.runtimeClassName) && object.spec.runtimeClassName == '{APPROVED}' && ({containers}).all(c, c.image == '{IMAGE}')"
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail",
                         "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                                "operations": ["CREATE"], "resources": ["pods"]}]},
                         "validations": [{"expression": predicate, "message": DENIAL}]}})
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"], "matchResources": {
                    "namespaceSelector": {"matchLabels": {"fixture.example/runtime-policy": "true"}}}}})


def rejected(lab, pod):
    out = lab.create(pod, dry_run=True, allow_failure=True)
    return out.returncode != 0 and DENIAL in out.stderr


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted",
                "fixture.example/runtime-policy=true")
    for name in (APPROVED, ALTERNATE):
        lab.create({"apiVersion": "node.k8s.io/v1", "kind": "RuntimeClass", "metadata": {"name": name}, "handler": "runc"})
    other_runtime = workload(ALTERNATE, IMAGE)
    before = lab.create(other_runtime, dry_run=True, allow_failure=True).returncode == 0
    lab.check("red", "The alternate runtime declaration is accepted before the enforcement policy",
              before, {"unreviewed_runtime_initially_admitted": before})

    policy(lab)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if rejected(lab, other_runtime):
            break
        time.sleep(0.4)
    else:
        lab.block("The approved runtime policy did not produce the expected denial")
    mutable = rejected(lab, workload(APPROVED, IMAGE.split("@", 1)[0]))
    lab.check("green", "The API rejects the alternate RuntimeClass and the mutable image reference",
              mutable, {"unreviewed_runtime_denied": True, "mutable_image_denied": mutable})

    lab.create(workload(APPROVED, IMAGE))
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{NAME}", "--timeout=60s", timeout=70)
    pod = json.loads(lab.kubectl("get", "pod", NAME, "-o", "json").stdout)
    deadline = time.monotonic() + 15
    receipt = ""
    while time.monotonic() < deadline:
        receipt = lab.kubectl("logs", NAME).stdout.strip()
        if receipt:
            break
        time.sleep(0.4)
    approved = pod["spec"]["runtimeClassName"] == APPROVED and receipt == "reviewed-runtime-marker"
    lab.check("positive", "The workload runs and emits the expected marker through the approved fixture RuntimeClass",
              approved, {"approved_runtime_workload_observed": approved})
    (lab.evidence / "toolkit-admission-observations.json").write_text(json.dumps({
        "alternate_initially_admitted": before, "alternate_runtime_denied": True, "mutable_image_denied": mutable,
        "approved_runtime_workload_observed": approved, "nvidia_runtime_exercised": False}, indent=2) + "\n")
