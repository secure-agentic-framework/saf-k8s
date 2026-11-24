"""Exercise AppArmor approval for all Kubernetes container lists."""

import json
import time
from pathlib import Path

from fixtures import container, pod

NS = "saf-test"
LABEL = "saf.example.org/apparmor-scope"
NAME = "fixture-approved-apparmor.saf.example.org"
MESSAGE = "effective AppArmor profile must be explicitly approved"
EXCEPTION_MESSAGES = {
    "namespace": "unconfined exception namespace does not match",
    "workload": "unconfined exception direct Pod name does not match",
    "identity": "unconfined exception requester does not match",
    "revoked": "unconfined exception is revoked",
    "interval": "unconfined exception is outside its fixture interval",
    "protection": "unconfined exception requires RuntimeDefault seccomp on all containers and disabled token automount",
}
LOCAL = {"type": "Localhost", "localhostProfile": "saf-approved-fixture"}
WRONG = {"type": "Localhost", "localhostProfile": "saf-unapproved-fixture"}
UNCONFINED = {"type": "Unconfined"}
DEFAULT = {"type": "RuntimeDefault"}
CONTROL_NS = "saf-control"
EXCEPTION_NAME = "fixture-apparmor-exception"
EXCEPTION_WORKLOAD = "fixture-unconfined-exception"
EXCEPTION_IDENTITY = "system:serviceaccount:saf-test:exception-evaluator"
APPLICANT_IDENTITY = "system:serviceaccount:saf-test:applicant"
# Fixed clock supplied by the fixture controller, independent of applicants.
FIXTURE_NOW = "2026-11-24T12:00:00Z"
SCOPE = (
    "Verify approved AppArmor inheritance and overrides across Kubernetes container types. "
    "An exact named direct Pod and requester may receive a dry-run exception under an "
    "externally owned grant, bounded fixture time and required compensating safeguards. "
    "All exception requests are dry-run only."
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
    approved_pod_default = ("has(object.spec.securityContext) && has(object.spec.securityContext.appArmorProfile) && "
                            "object.spec.securityContext.appArmorProfile.type == 'Localhost' && "
                            "has(object.spec.securityContext.appArmorProfile.localhostProfile) && "
                            f"object.spec.securityContext.appArmorProfile.localhostProfile == '{LOCAL['localhostProfile']}'")
    unconfined_pod_default = ("has(object.spec.securityContext) && has(object.spec.securityContext.appArmorProfile) && "
                              "object.spec.securityContext.appArmorProfile.type == 'Unconfined'")
    default_seccomp = (
        "has(object.spec.securityContext) && has(object.spec.securityContext.seccompProfile) && "
        "object.spec.securityContext.seccompProfile.type == 'RuntimeDefault'"
    )
    seccomp = (
        "(has(c.securityContext) && has(c.securityContext.seccompProfile) ? "
        "c.securityContext.seccompProfile.type == 'RuntimeDefault' : (" + default_seccomp + "))"
    )
    protection = " && ".join((
        "(has(object.spec.automountServiceAccountToken) && !object.spec.automountServiceAccountToken)",
        f"object.spec.containers.all(c, {seccomp})",
        f"(!has(object.spec.initContainers) || object.spec.initContainers.all(c, {seccomp}))",
        f"(!has(object.spec.ephemeralContainers) || object.spec.ephemeralContainers.all(c, {seccomp}))",
    ))
    exception_checks = {
        "namespace": "params.data.namespace == object.metadata.namespace",
        "workload": (
            "(!has(object.metadata.ownerReferences) || size(object.metadata.ownerReferences) == 0) && "
            f"params.data.workloadName == '{EXCEPTION_WORKLOAD}' && "
            "params.data.workloadName == object.metadata.name"
        ),
        "identity": "params.data.identity == request.userInfo.username",
        "revoked": "params.data.revoked == 'false'",
        "interval": (
            "timestamp(params.data.fixtureNow) >= timestamp(params.data.notBefore) && "
            "timestamp(params.data.fixtureNow) < timestamp(params.data.expiresAt)"
        ),
        "protection": protection,
    }
    # A Pod-level exception permits inherited Unconfined only. Explicit
    # per-container overrides still need the approved Localhost profile.
    pod_default = f"({approved_pod_default}) || ({unconfined_pod_default})"
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
                         "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
                         "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                                "operations": ["CREATE", "UPDATE"],
                                                                "resources": ["pods", "pods/ephemeralcontainers"]}]},
                         "variables": [{"name": "approvedPodDefault", "expression": pod_default}],
                         "validations": validations + [
                             {"expression": f"!({unconfined_pod_default}) || ({expression})",
                              "message": EXCEPTION_MESSAGES[key]}
                             for key, expression in exception_checks.items()
                         ]}})
    lab.create({"apiVersion": v1, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": NAME},
                "spec": {"policyName": NAME, "validationActions": ["Deny"],
                         "paramRef": {"name": EXCEPTION_NAME, "namespace": CONTROL_NS,
                                      "parameterNotFoundAction": "Deny"},
                         "matchResources": {"namespaceSelector": {"matchLabels": {LABEL: "named-profile"}}}}})


def rejected(response):
    return response.returncode != 0 and NAME in response.stderr and MESSAGE in response.stderr


def exception_record(**changes):
    data = {"namespace": NS, "workloadName": EXCEPTION_WORKLOAD, "identity": EXCEPTION_IDENTITY,
            "notBefore": "2026-11-24T11:00:00Z", "expiresAt": "2026-11-24T13:00:00Z",
            "fixtureNow": FIXTURE_NOW, "revoked": "false"}
    data.update(changes)
    return {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": EXCEPTION_NAME, "namespace": CONTROL_NS}, "data": data}


def set_exception_record(lab, **changes):
    lab.kubectl("-n", CONTROL_NS, "apply", "--server-side", "-f", "-", "-o", "name",
                payload=json.dumps(exception_record(**changes)))


def grant_pod_admission(lab):
    for identity in (EXCEPTION_IDENTITY, APPLICANT_IDENTITY):
        lab.kubectl("create", "serviceaccount", identity.split(":")[-1])
    lab.kubectl("create", "role", "fixture-pod-submitter", "--verb=create", "--resource=pods")
    lab.kubectl("create", "rolebinding", "fixture-pod-submitter", "--role=fixture-pod-submitter",
                "--serviceaccount=" + NS + ":" + EXCEPTION_IDENTITY.split(":")[-1],
                "--serviceaccount=" + NS + ":" + APPLICANT_IDENTITY.split(":")[-1])


def exception_attempt(lab, identity=EXCEPTION_IDENTITY, probe=None):
    # Keep Unconfined Pods inert even when the exception is accepted.
    fixture = probe if probe is not None else workload(EXCEPTION_WORKLOAD, UNCONFINED)
    return lab.kubectl(f"--as={identity}", "create", "-f", "-", "--dry-run=server", "-o", "name",
                       payload=json.dumps(fixture), allow_failure=True)


def converge(action, expected):
    deadline = time.monotonic() + 18
    while True:
        response = action()
        if expected(response) or time.monotonic() >= deadline:
            return response
        time.sleep(0.4)


def verify_exceptions(lab):
    def accepted(response):
        return response.returncode == 0 and response.stdout.strip() == "pod/" + EXCEPTION_WORKLOAD

    def denied(response, reason):
        return (response.returncode != 0 and NAME in response.stderr
                and EXCEPTION_MESSAGES[reason] in response.stderr)

    active = converge(lambda: exception_attempt(lab), accepted)
    lab.check("positive", "An active grant admits the exact direct Pod and requester for a dry run",
              accepted(active), {"active_exact_scope_accepted": accepted(active)})
    results = {}
    for reason, description, overrides in (
        ("interval", "expired", {"expiresAt": "2026-11-24T11:59:59Z"}),
        ("interval", "not_yet_active", {"notBefore": "2026-11-24T12:00:01Z"}),
        ("revoked", "revoked", {"revoked": "true"}),
        ("namespace", "wrong_namespace", {"namespace": "other-namespace"}),
        ("workload", "wrong_name", {"workloadName": "different-pod"}),
        ("identity", "wrong_record_identity", {"identity": APPLICANT_IDENTITY}),
    ):
        # Observe a known active grant between invalid updates so a stale
        # previous denial cannot serve as evidence for the next grant.
        set_exception_record(lab)
        if not accepted(converge(lambda: exception_attempt(lab), accepted)):
            lab.block("The active grant did not propagate before " + description)
        set_exception_record(lab, **overrides)
        trial = converge(lambda: exception_attempt(lab), lambda response: denied(response, reason))
        results[description] = denied(trial, reason)

    set_exception_record(lab)
    if not accepted(converge(lambda: exception_attempt(lab), accepted)):
        lab.block("The active grant did not propagate before subject and protection checks")
    wrong_requester = exception_attempt(lab, identity=APPLICANT_IDENTITY)
    results["wrong_requester"] = denied(wrong_requester, "identity")

    no_filter = workload(EXCEPTION_WORKLOAD, UNCONFINED)
    no_filter["spec"]["initContainers"][0]["securityContext"].pop("seccompProfile")
    results["missing_effective_seccomp"] = denied(exception_attempt(lab, probe=no_filter), "protection")
    with_token = workload(EXCEPTION_WORKLOAD, UNCONFINED)
    with_token["spec"]["automountServiceAccountToken"] = True
    results["enabled_token_automount"] = denied(exception_attempt(lab, probe=with_token), "protection")

    record = exception_record()
    target = f"/api/v1/namespaces/{CONTROL_NS}/configmaps/{EXCEPTION_NAME}?dryRun=All"
    for identity in (EXCEPTION_IDENTITY, APPLICANT_IDENTITY):
        change = lab.kubectl(f"--as={identity}", "replace", "--raw", target, "-f", "-",
                            payload=json.dumps(record), allow_failure=True)
        patch = lab.kubectl(f"--as={identity}", "-n", CONTROL_NS, "auth", "can-i", "patch",
                           "configmap/" + EXCEPTION_NAME, allow_failure=True)
        results[identity.split(":")[-1] + "_cannot_edit_grant"] = (
            change.returncode != 0 and "(Forbidden)" in change.stderr
            and 'cannot update resource "configmaps"' in change.stderr
            and patch.returncode == 1 and patch.stdout.strip() == "no"
        )

    results["no_exception_pod_created"] = (
        "(NotFound)" in lab.kubectl("get", "pod", EXCEPTION_WORKLOAD, allow_failure=True).stderr
    )
    if not all(results.values()):
        (lab.evidence / "exception-assertions.json").write_text(json.dumps(results, indent=2) + "\n")
    lab.check("green", "The policy denies invalid grants and missing safeguards, and submitters cannot edit the grant",
              all(results.values()), results)
    return {"active_exact_scope_accepted": accepted(active), **results}


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
    lab.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": CONTROL_NS}})
    grant_pod_admission(lab)
    set_exception_record(lab)
    install_policy(lab)
    baseline_policy = converge(lambda: lab.create(unprofiled, dry_run=True, allow_failure=True), rejected)
    if not rejected(baseline_policy):
        lab.block("The named-profile policy did not reach its expected omission denial")

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

    exception_results = verify_exceptions(lab)

    (lab.evidence / "apparmor-admission-observations.json").write_text(json.dumps({
        "approved_local_profile": LOCAL["localhostProfile"], "pre_binding_omission_admitted": baseline,
        "pre_binding_ephemeral_override_admitted": baseline_ephemeral, "scope_denials": denials,
        "scope_positive_cases": accepted, "node_enforcement_tested": False,
        "exception_path_tested": True, "exception_results": exception_results,
        "fixture_time": FIXTURE_NOW,
    }, indent=2) + "\n")
