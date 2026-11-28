"""Verify evidence-based scheduling eligibility for two inert accelerator profiles."""

import json
from pathlib import Path
import runpy
import time

SCOPE = "Real Kubernetes admission and scheduler placement against modeled dedicated and shared accelerator profiles, plus a live expiration check for an exact immutable exception."
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
API = "admissionregistration.k8s.io/v1"
RBAC = "rbac.authorization.k8s.io"
PROFILE = "fixture.example/accelerator-profile"
SCOPE_LABEL = "fixture.example/profile-review"
RESOURCE = "fixture.example/accelerator"
POLICY = "fixture-accelerator-eligibility"
MESSAGE = "The fixture workload needs an approved accelerator placement profile"
SENSITIVE = "fixture-sensitive-owner"
ROUTINE = "fixture-routine-owner"


def prepare_kind(_lab, temporary):
    config = temporary / "kind-accelerator-eligibility.yaml"
    config.write_text("""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
""")
    return config


def configure_profiles(lab):
    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    profiles = {}
    path = RESOURCE.replace("/", "~1")
    for node in nodes:
        name = node["metadata"]["name"]
        labels = node["metadata"]["labels"]
        profile = "shared" if "node-role.kubernetes.io/control-plane" in labels else "dedicated"
        profiles[profile] = name
        lab.kubectl("label", "node", name, f"{PROFILE}={profile}")
        lab.kubectl("patch", "node", name, "--subresource=status", "--type=json", "-p",
                    json.dumps([{"op": "add", "path": f"/status/capacity/{path}", "value": "1"}]))
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        statuses = [node["status"] for node in json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]]
        if set(profiles) == {"dedicated", "shared"} and all(s.get("allocatable", {}).get(RESOURCE) == "1" for s in statuses):
            return profiles
        time.sleep(0.5)
    lab.block("The expected two fixture nodes and modeled capacity were unavailable")


def pod(name, profile):
    spec = {"automountServiceAccountToken": False, "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "marker", "image": IMAGE, "command": ["python", "-c", "print('fixture-placed')"],
                            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                "capabilities": {"drop": ["ALL"]}},
                            "resources": {"limits": {RESOURCE: "1", "cpu": "100m", "memory": "48Mi"},
                                          "requests": {"cpu": "5m", "memory": "12Mi"}}}]}
    if profile is not None:
        spec["nodeSelector"] = {PROFILE: profile}
    if profile == "shared":
        spec["tolerations"] = [{"key": "node-role.kubernetes.io/control-plane", "operator": "Exists", "effect": "NoSchedule"}]
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": spec}


def submit(lab, subject, manifest, *, dry_run=True):
    flags = ["--dry-run=server"] if dry_run else []
    return lab.kubectl("--as", subject, "create", "-f", "-", "-o", "json", *flags,
                       payload=json.dumps(manifest), allow_failure=True)


def eligibility_expression(exception=None):
    cases = [
        f"request.userInfo.username == '{SENSITIVE}' && object.spec.nodeSelector['{PROFILE}'] == 'dedicated'",
        f"request.userInfo.username == '{ROUTINE}' && object.spec.nodeSelector['{PROFILE}'] == 'shared'",
    ]
    if exception:
        cases.append(exception)
    approved = " || ".join(f"({item})" for item in cases)
    return ("(!has(object.spec.nodeName) || object.spec.nodeName == '') && "
            f"has(object.spec.nodeSelector) && '{PROFILE}' in object.spec.nodeSelector && ({approved})")


def activate_exception(lab, requirement):
    patch = [{"op": "replace", "path": "/spec/validations/0/expression",
              "value": eligibility_expression(requirement)}]
    lab.kubectl("patch", "validatingadmissionpolicy", POLICY, "--type=json", "-p", json.dumps(patch))


def enforce(lab):
    predicate = eligibility_expression()
    lab.create({"apiVersion": API, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail", "matchConstraints": {"resourceRules": [{
                    "apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"],
                }]}, "validations": [{"expression": predicate, "message": MESSAGE}]}})
    lab.create({"apiVersion": API, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"], "matchResources": {
                    "namespaceSelector": {"matchLabels": {SCOPE_LABEL: "true"}}}}})


def rejected(result):
    return result.returncode != 0 and MESSAGE in result.stderr


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", f"{SCOPE_LABEL}=true", "pod-security.kubernetes.io/enforce=restricted")
    profiles = configure_profiles(lab)
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "Role", "metadata": {"name": POLICY},
                "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}]})
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "RoleBinding", "metadata": {"name": POLICY},
                "roleRef": {"apiGroup": RBAC, "kind": "Role", "name": POLICY},
                "subjects": [{"apiGroup": RBAC, "kind": "User", "name": user} for user in (SENSITIVE, ROUTINE)]})
    shared = pod("fixture-shared-sensitive", "shared")
    initial = submit(lab, SENSITIVE, shared).returncode == 0
    lab.check("red", "The sensitive workload's shared profile is admitted before eligibility policy is enabled", initial,
              {"shared_sensitive_initially_admitted": initial})
    enforce(lab)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if rejected(submit(lab, SENSITIVE, shared)):
            break
        time.sleep(0.4)
    else:
        lab.block("The eligibility policy did not deny this sensitive workload's shared placement")
    missing = rejected(submit(lab, SENSITIVE, pod("fixture-unknown", None)))
    unexpected = rejected(submit(lab, ROUTINE, pod("fixture-unapproved", "unapproved")))
    lab.check("green", "The API rejects sensitive shared placement and missing or unapproved inventory profiles",
              missing and unexpected, {"sensitive_shared_denied": True, "missing_profile_denied": missing,
                                       "unapproved_profile_denied": unexpected})

    actual = {}
    for owner, profile in ((SENSITIVE, "dedicated"), (ROUTINE, "shared")):
        name = f"fixture-valid-{profile}"
        if submit(lab, owner, pod(name, profile), dry_run=False).returncode != 0:
            lab.block(f"The API did not admit the expected {profile} fixture")
        lab.kubectl("wait", "--for=condition=PodScheduled", f"pod/{name}", "--timeout=55s", timeout=64)
        actual[profile] = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)["spec"]["nodeName"]
    lab.check("positive", "The scheduler assigns both accepted workloads to their distinct expected inventory nodes",
              actual == profiles, {"dedicated_node_match": actual["dedicated"] == profiles["dedicated"],
                                   "shared_node_match": actual["shared"] == profiles["shared"]})
    (lab.evidence / "accelerator-placement-observations.json").write_text(json.dumps({
        "profiles": sorted(actual), "distinct_nodes": len(set(actual.values())) == 2, "hardware_isolation_tested": False,
    }, indent=2) + "\n")

    mig_profile = runpy.run_path(str(Path(__file__).with_name("mig_profile_case.py")))
    mig_profile["run"](lab)

    expiry = runpy.run_path(str(Path(__file__).with_name("exception_expiry.py")))
    expiry["run"](lab, pod, submit, activate_exception)
