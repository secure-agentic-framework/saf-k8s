"""Verify a fail-closed scheduling decision for a modeled confidential runtime."""

from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import time

SCOPE = "Live admission and scheduling for modeled confidential placement plus a pre-use denial driven by separately authenticated archived CPU and GPU evidence."
NAME = "fixture-sensitive-workload"
RUNTIME = "fixture-reviewed-confidential"
ORDINARY = "fixture-ordinary-runtime"
LABEL = "fixture.example.node-restriction.kubernetes.io/reviewed-confidential"
POLICY = "fixture-confidential-placement"
DENIAL = "Sensitive workload requires the reviewed fixture runtime and placement"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"


def pod(runtime, *, placement=True):
    spec = {"restartPolicy": "Never", "runtimeClassName": runtime, "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "fixture", "image": IMAGE, "command": ["python", "-c", "import time; time.sleep(150)"],
                            "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                                          "limits": {"cpu": "100m", "memory": "40Mi"}},
                            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                "capabilities": {"drop": ["ALL"]}}}]}
    if placement:
        spec["nodeSelector"] = {LABEL: "true"}
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": NAME}, "spec": spec}


def gate(lab):
    api = "admissionregistration.k8s.io/v1"
    rule = (f"has(object.spec.runtimeClassName) && object.spec.runtimeClassName == '{RUNTIME}' && "
            f"!has(object.spec.nodeName) && has(object.spec.nodeSelector) && "
            f"'{LABEL}' in object.spec.nodeSelector && object.spec.nodeSelector['{LABEL}'] == 'true'")
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail",
                         "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                                "operations": ["CREATE"], "resources": ["pods"]}]},
                         "validations": [{"expression": rule, "message": DENIAL}]}})
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"], "matchResources": {
                    "namespaceSelector": {"matchLabels": {"fixture.example/sensitive-placement": "true"}}}}})


def rejected(lab, request):
    out = lab.create(request, dry_run=True, allow_failure=True)
    return out.returncode != 0 and DENIAL in out.stderr


def read(lab):
    return json.loads(lab.kubectl("get", "pod", NAME, "-o", "json").stdout)


def unscheduled(lab):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        actual = read(lab)
        if actual["spec"].get("nodeName"):
            return False
        for state in actual.get("status", {}).get("conditions", []):
            if state.get("type") == "PodScheduled" and state.get("reason") == "Unschedulable" and "node affinity/selector" in state.get("message", ""):
                return True
        time.sleep(0.5)
    lab.block("The scheduler did not give an attributable selector decision")


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted",
                "fixture.example/sensitive-placement=true")
    for name in (RUNTIME, ORDINARY):
        lab.create({"apiVersion": "node.k8s.io/v1", "kind": "RuntimeClass", "metadata": {"name": name}, "handler": "runc"})
    bad = pod(ORDINARY)
    admitted = lab.create(bad, dry_run=True, allow_failure=True).returncode == 0
    lab.check("red", "The ordinary runtime is admitted before the sensitive workload policy",
              admitted, {"ordinary_runtime_admitted_initially": admitted})
    gate(lab)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if rejected(lab, bad):
            break
        time.sleep(0.4)
    else:
        lab.block("The API did not produce the expected sensitive workload denial")
    missing = rejected(lab, pod(RUNTIME, placement=False))
    lab.create(pod(RUNTIME))
    waiting = unscheduled(lab)
    lab.check("green", "Admission requires declared scope, and the actual scheduler waits for the approved node label",
              missing and waiting, {"ordinary_runtime_denied": True, "missing_placement_denied": missing,
                                    "approved_fixture_waits_without_node_label": waiting})
    node, = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    node_name = node["metadata"]["name"]
    lab.kubectl("label", "node", node_name, f"{LABEL}=true")
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{NAME}", "--timeout=60s", timeout=70)
    final = read(lab)
    matched = final["spec"]["nodeName"] == node_name and final["spec"]["runtimeClassName"] == RUNTIME
    lab.check("positive", "The same pending fixture schedules and becomes Ready after the modeled host approval label",
              matched, {"same_fixture_ready_in_approved_scope": matched})
    (lab.evidence / "confidential-placement-observations.json").write_text(json.dumps({
        "ordinary_runtime_admitted_initially": admitted, "ordinary_runtime_denied": True,
        "missing_placement_denied": missing, "waited_before_fixture_approval": waiting,
        "expected_placement_ready": matched, "tee_or_memory_encryption_tested": False}, indent=2) + "\n")

    reference = spec_from_file_location("saf_0804_001_azure_hcl", Path(__file__).with_name("hcl_reference.py"))
    module = module_from_spec(reference)
    reference.loader.exec_module(module)
    module.run(lab, pod(RUNTIME))
