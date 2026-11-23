"""Exercise AppArmor approval for all Kubernetes container lists."""

import json
import time
from pathlib import Path

from fixtures import container, pod

NS = "saf-test"
LABEL = "saf.example.org/apparmor-scope"
NAME = "fixture-approved-apparmor.saf.example.org"
MESSAGE = "effective AppArmor profile must be explicitly approved"
LOCAL = {"type": "Localhost", "localhostProfile": "saf-approved-fixture"}
WRONG = {"type": "Localhost", "localhostProfile": "saf-unapproved-fixture"}
UNCONFINED = {"type": "Unconfined"}
DEFAULT = {"type": "RuntimeDefault"}
SCOPE = (
    "Test explicit AppArmor approval, inheritance and overrides for ordinary, init and "
    "ephemeral containers on the Kubernetes API. Use scheduling gates for named-profile "
    "fixtures so their API acceptance does not imply node enforcement."
)


def unit(name, profile=None):
    obj = container(name, command=["sh", "-c", "exit 0"])
    if profile is not None:
        obj["securityContext"]["appArmorProfile"] = profile
    return obj


def workload(name, profile=None, app=None, init=None):
    fields = {"initContainers": [unit("init", init)], "automountServiceAccountToken": False,
              "schedulingGates": [{"name": "saf.example.org/hold-profile-fixture"}]}
    if profile is not None:
        fields["securityContext"] = {"appArmorProfile": profile}
    return pod(name, [unit("workload", app)], **fields)


def install_policy(lab):
    # The named-profile namespace intentionally uses one approved policy class.
    # The retained predicate evaluates the per-container choice before the Pod default.
    pod_default = ("has(object.spec.securityContext) && has(object.spec.securityContext.appArmorProfile) && "
                   "object.spec.securityContext.appArmorProfile.type == 'Localhost' && "
                   "has(object.spec.securityContext.appArmorProfile.localhostProfile) && "
                   f"object.spec.securityContext.appArmorProfile.localhostProfile == '{LOCAL['localhostProfile']}'")
    container_profile = ("has(c.securityContext) && has(c.securityContext.appArmorProfile) ? "
                         "(c.securityContext.appArmorProfile.type == 'Localhost' && "
                         "has(c.securityContext.appArmorProfile.localhostProfile) && "
                         f"c.securityContext.appArmorProfile.localhostProfile == '{LOCAL['localhostProfile']}') "
                         ": variables.approvedPodDefault")
    validations = [{"expression": expression, "message": MESSAGE} for expression in (
        f"object.spec.containers.all(c, {container_profile})",
        f"!has(object.spec.initContainers) || object.spec.initContainers.all(c, {container_profile})",
        f"!has(object.spec.ephemeralContainers) || object.spec.ephemeralContainers.all(c, {container_profile})",
        "!has(object.metadata.annotations) || "
        "!object.metadata.annotations.exists(k, k.startsWith('container.apparmor.security.beta.kubernetes.io/'))",
    )]
    v1 = "admissionregistration.k8s.io/v1"
    lab.create({"apiVersion": v1, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": NAME},
                "spec": {"failurePolicy": "Fail",
                         "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                                "operations": ["CREATE", "UPDATE"],
                                                                "resources": ["pods", "pods/ephemeralcontainers"]}]},
                         "variables": [{"name": "approvedPodDefault", "expression": pod_default}],
                         "validations": validations}})
    lab.create({"apiVersion": v1, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": NAME},
                "spec": {"policyName": NAME, "validationActions": ["Deny"], "matchResources": {
                    "namespaceSelector": {"matchLabels": {LABEL: "named-profile"}}}}})


def rejected(response):
    return response.returncode != 0 and NAME in response.stderr and MESSAGE in response.stderr


def ephemeral(lab, profile=None):
    patch = {"spec": {"ephemeralContainers": [unit("debug-marker", profile)]}}
    return lab.kubectl("patch", "pod/fixture-ephemeral-parent", "--subresource=ephemeralcontainers",
                       "--type=merge", "-p", json.dumps(patch), "--dry-run=server", "-o", "name",
                       allow_failure=True)


def run(lab):
    unprofiled = workload("fixture-omitted")
    lab.kubectl("label", "namespace", NS, f"{LABEL}=named-profile")
    lab.create(workload("fixture-ephemeral-parent", LOCAL))
    lab.kubectl("wait", "--for=jsonpath={.status.conditions[?(@.type=='PodScheduled')].reason}=SchedulingGated",
                "pod/fixture-ephemeral-parent", "--timeout=30s", timeout=40)
    baseline = lab.create(unprofiled, dry_run=True, allow_failure=True).returncode == 0
    baseline_ephemeral = ephemeral(lab, UNCONFINED).returncode == 0
    lab.check("red", "The API accepts omission and an unconfined ephemeral override before the scoped policy",
              baseline and baseline_ephemeral, {"omission_accepted": baseline, "ephemeral_override_accepted": baseline_ephemeral})
    install_policy(lab)

    deadline = time.monotonic() + 24
    while time.monotonic() < deadline:
        if rejected(lab.create(unprofiled, dry_run=True, allow_failure=True)):
            break
        time.sleep(0.6)

    annotation_only = workload("fixture-legacy-annotation")
    annotation_only["metadata"]["annotations"] = {
        "container.apparmor.security.beta.kubernetes.io/workload": "localhost/saf-approved-fixture"}
    cases = {
        "omission": unprofiled,
        "wrong_pod_profile": workload("fixture-wrong-name", WRONG),
        "unconfined_app_override": workload("fixture-app-override", LOCAL, app=UNCONFINED),
        "unapproved_init_override": workload("fixture-init-override", LOCAL, init=WRONG),
        "runtime_default_not_the_approved_class": workload("fixture-runtime-default", DEFAULT),
        "deprecated_annotation": annotation_only,
    }
    denials = {name: rejected(lab.create(spec, dry_run=True, allow_failure=True)) for name, spec in cases.items()}
    denials["unconfined_ephemeral_override"] = rejected(ephemeral(lab, UNCONFINED))
    denials["unapproved_ephemeral_override"] = rejected(ephemeral(lab, WRONG))
    lab.check("green", "The named-profile policy denies missing, unapproved and unconfined requests across every container list",
              all(denials.values()), denials)

    accepted = {
        "inherit_pod_default": lab.create(workload("fixture-inherits", LOCAL), dry_run=True, allow_failure=True).returncode == 0,
        "explicit_per_container": lab.create(workload("fixture-direct", app=LOCAL, init=LOCAL),
                                             dry_run=True, allow_failure=True).returncode == 0,
        "ephemeral_inherits": ephemeral(lab).returncode == 0,
        "ephemeral_explicit": ephemeral(lab, LOCAL).returncode == 0,
    }
    lab.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "fixture-apparmor-unselected"}})
    unselected = workload("fixture-unselected")
    unselected["metadata"]["namespace"] = "fixture-apparmor-unselected"
    accepted["unselected_namespace"] = lab.kubectl("-n", "fixture-apparmor-unselected", "create", "-f", "-",
        "--dry-run=server", "-o", "name", payload=json.dumps(unselected), allow_failure=True).returncode == 0
    lab.check("positive", "Approved inheritance and explicit profiles pass, including ephemeral updates, and the unselected namespace is unaffected",
              all(accepted.values()), accepted)
    (lab.evidence / "apparmor-admission-observations.json").write_text(json.dumps({
        "approved_local_profile": LOCAL["localhostProfile"], "pre_binding_omission_admitted": baseline,
        "pre_binding_ephemeral_override_admitted": baseline_ephemeral, "scope_denials": denials,
        "scope_positive_cases": accepted, "node_enforcement_tested": False, "exception_path_tested": False,
    }, indent=2) + "\n")
