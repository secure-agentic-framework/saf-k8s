"""Validate a risk decision excluding restricted workloads from a modeled sharing mode."""

import json
import time

SCOPE = "Actual Kubernetes admission enforcement for a synthetic accelerator risk decision and workload classification."
PREFIX = "fixture.example/accelerator-"
POLICY = "fixture-accelerator-risk"
MESSAGE = "Restricted workloads require an approved dedicated allocation"
RESTRICTED = "saf-test"
LOWER = "saf-reviewed-class"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"


def request(lab, ns, name, profile, *, dry_run=True):
    flags = ["--dry-run=server"] if dry_run else []
    pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
           "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never",
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{"name": "fixture", "image": IMAGE, "command": ["python", "-c", "import time; time.sleep(140)"],
                                    "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                                                  "limits": {"cpu": "100m", "memory": "40Mi", PREFIX + profile: "1"}},
                                    "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                        "capabilities": {"drop": ["ALL"]}}}]}}
    return lab.kubectl("--namespace", ns, "create", "-f", "-", "-o", "json", *flags,
                       payload=json.dumps(pod), allow_failure=True)


def install(lab):
    api = "admissionregistration.k8s.io/v1"
    all_containers = "object.spec.containers + (has(object.spec.initContainers) ? object.spec.initContainers : [])"
    map_rules = [f"(!has(c.resources.{field}) || c.resources.{field}.all(key, "
                 f"!key.startsWith('{PREFIX}') || key == '{PREFIX}approved-dedicated'))"
                 for field in ("requests", "limits")]
    rule = f"({all_containers}).all(c, !has(c.resources) || ({' && '.join(map_rules)}))"
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail",
                         "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                                "operations": ["CREATE"], "resources": ["pods"]}]},
                         "validations": [{"expression": rule, "message": MESSAGE}]}})
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"], "matchResources": {
                    "namespaceSelector": {"matchLabels": {"fixture.example/risk-class": "restricted"}}}}})


def blocked(response):
    return response.returncode != 0 and MESSAGE in response.stderr


def run(lab):
    lab.kubectl("create", "namespace", LOWER)
    for ns, classification in ((RESTRICTED, "restricted"), (LOWER, "approved-single-trust")):
        lab.kubectl("label", "namespace", ns, "pod-security.kubernetes.io/enforce=restricted",
                    f"fixture.example/risk-class={classification}")
    baseline = request(lab, RESTRICTED, "shared-before", "modeled-shared").returncode == 0
    lab.check("red", "The restricted fixture can declare shared use before enforcing the risk decision",
              baseline, {"restricted_shared_initially_admitted": baseline})

    install(lab)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if blocked(request(lab, RESTRICTED, "restricted-shared", "modeled-shared")):
            break
        time.sleep(0.4)
    else:
        lab.block("The risk policy did not produce the reviewed denial")
    unknown_denied = blocked(request(lab, RESTRICTED, "restricted-unknown", "unknown"))
    lab.check("green", "Restricted workload admission denies the unapproved shared and unknown fixture profiles",
              unknown_denied, {"restricted_shared_denied": True, "unknown_profile_denied": unknown_denied})

    node, = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    new_capacity = [{"op": "add", "path": "/status/capacity/" + (PREFIX + profile).replace("/", "~1"), "value": "1"}
                    for profile in ("approved-dedicated", "modeled-shared")]
    lab.kubectl("patch", "node", node["metadata"]["name"], "--subresource=status", "--type=json",
                "-p", json.dumps(new_capacity))
    approved = {}
    for ns, profile in ((RESTRICTED, "approved-dedicated"), (LOWER, "modeled-shared")):
        name = "approved-risk-fixture"
        response = request(lab, ns, name, profile, dry_run=False)
        if response.returncode:
            lab.block("An approved fixture Pod could not be admitted")
        lab.kubectl("--namespace", ns, "wait", "--for=condition=Ready", f"pod/{name}", "--timeout=60s", timeout=70)
        data = json.loads(lab.kubectl("--namespace", ns, "get", "pod", name, "-o", "json").stdout)
        resources = data["spec"]["containers"][0]["resources"]["requests"]
        approved[ns] = bool(data["spec"].get("nodeName")) and resources.get(PREFIX + profile) == "1"
    lab.check("positive", "The restricted dedicated declaration and the separately scoped lower-trust fixture both run",
              all(approved.values()), {"approved_profile_by_namespace": approved})
    (lab.evidence / "accelerator-risk-observations.json").write_text(json.dumps(
        {"initial_restricted_shared_admitted": baseline, "restricted_shared_denied": True,
         "unknown_profile_denied": unknown_denied, "approved_declarations_running": approved,
         "accelerator_security_properties_measured": False}, indent=2) + "\n")
