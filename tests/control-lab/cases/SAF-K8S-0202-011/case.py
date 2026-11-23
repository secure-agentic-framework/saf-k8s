"""Test the distinction between admission, an available MAC policy, and workload operation."""

import json
import time

SCOPE = "Kubernetes admission and kubelet handling of one intentionally unavailable AppArmor declaration on disposable Kind."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
API = "admissionregistration.k8s.io/v1"
POLICY = "fixture-required-apparmor"
LABEL = "fixture.example/required-apparmor"
PROFILE = "fixture-approved-but-unavailable"
MESSAGE = "Fixture workload must declare the named MAC profile"
NS = "saf-test"


def pod(name, namespace=NS, *, profile=False, override=False):
    container = {"name": "unit", "image": IMAGE, "command": ["python", "-c", "print('fixture completed')"],
                 "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}},
                 "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                               "limits": {"cpu": "100m", "memory": "48Mi"}}}
    spec = {"automountServiceAccountToken": False, "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [container]}
    if profile:
        spec["securityContext"]["appArmorProfile"] = {"type": "Localhost", "localhostProfile": PROFILE}
    if override:
        container["securityContext"]["appArmorProfile"] = {"type": "Unconfined"}
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": namespace}, "spec": spec}


def validation(lab):
    declared = ("has(object.spec.securityContext) && has(object.spec.securityContext.appArmorProfile) && "
                "object.spec.securityContext.appArmorProfile.type == 'Localhost' && "
                f"object.spec.securityContext.appArmorProfile.localhostProfile == '{PROFILE}'")
    no_override = ("object.spec.containers.all(c, !has(c.securityContext) || "
                   "!has(c.securityContext.appArmorProfile)) && "
                   "(!has(object.spec.initContainers) || object.spec.initContainers.all(c, "
                   "!has(c.securityContext) || !has(c.securityContext.appArmorProfile)))")
    lab.create({"apiVersion": API, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail", "matchConstraints": {"resourceRules": [{
                    "apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"],
                }]}, "validations": [{"expression": f"({declared}) && ({no_override})", "message": MESSAGE}]}})
    lab.create({"apiVersion": API, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"], "matchResources": {
                    "namespaceSelector": {"matchLabels": {LABEL: "true"}}}}})


def dry(lab, manifest):
    return lab.create(manifest, dry_run=True, allow_failure=True)


def denied(result):
    return result.returncode != 0 and MESSAGE in result.stderr


def read(lab, name):
    return json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)


def runtime_refused(lab, name):
    deadline = time.monotonic() + 40
    observed = []
    while time.monotonic() < deadline:
        status = read(lab, name)["status"]
        states = [condition.get("state", {}) for condition in status.get("containerStatuses", [])]
        if status.get("phase") == "Succeeded" or any("running" in state for state in states):
            return False
        events = json.loads(lab.kubectl("get", "events", "--field-selector", f"involvedObject.name={name}",
                                       "-o", "json").stdout)["items"]
        observed = [str(status.get("message", "")), *(event.get("message", "") for event in events)]
        if any("apparmor" in message.lower() and any(word in message.lower() for word in
               ("unsupported", "not supported", "not enabled", "not loaded", "not found", "cannot")) for message in observed):
            return True
        time.sleep(0.8)
    lab.block("The fixture did not observe an attributable MAC-related runtime decision")


def run(lab):
    lab.kubectl("label", "namespace", NS, f"{LABEL}=true")
    unprofiled = pod("fixture-mac-omission")
    baseline = dry(lab, unprofiled).returncode == 0
    lab.check("red", "A workload without the intended MAC declaration is initially admitted", baseline,
              {"unprofiled_initially_admitted": baseline})
    validation(lab)
    deadline = time.monotonic() + 20
    omitted = False
    while time.monotonic() < deadline:
        omitted = denied(dry(lab, unprofiled))
        if omitted:
            break
        time.sleep(0.5)
    unauthorized = denied(dry(lab, pod("fixture-mac-override", profile=True, override=True)))
    manifest = pod("fixture-required", profile=True)
    intended = dry(lab, manifest).returncode == 0
    lab.check("green", "The API requires the named AppArmor profile and denies a conflicting container override",
              omitted and unauthorized and intended,
              {"omitted_profile_rejected": omitted, "conflicting_profile_rejected": unauthorized, "intended_profile_admitted": intended})

    lab.create(manifest)
    rejected = runtime_refused(lab, "fixture-required")
    other_ns = "fixture-mac-unconstrained"
    lab.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": other_ns}})
    lab.kubectl("-n", other_ns, "create", "-f", "-", payload=json.dumps(pod("fixture-ordinary", other_ns)))
    lab.kubectl("-n", other_ns, "wait", "--for=jsonpath={.status.phase}=Succeeded",
                "pod/fixture-ordinary", "--timeout=55s", timeout=65)
    marker = lab.kubectl("-n", other_ns, "logs", "pod/fixture-ordinary").stdout.strip() == "fixture completed"
    lab.check("positive", "Runtime refuses the unavailable profile while an unscoped public fixture still completes",
              rejected and marker, {"unavailable_apparmor_rejected": rejected, "ordinary_workload_completed": marker})
    (lab.evidence / "workload-mac-observations.json").write_text(json.dumps({
        "admission_profile_required": omitted and unauthorized, "unavailable_profile_refused": rejected,
        "ordinary_workload_completed": marker, "loaded_policy_confinement_tested": False,
    }, indent=2) + "\n")
