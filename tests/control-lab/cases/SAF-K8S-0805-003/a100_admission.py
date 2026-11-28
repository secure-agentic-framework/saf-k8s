"""Exercise the exact native decision path used by the owned A100 fixture."""

from copy import deepcopy
import json
import re
import time

API = "admissionregistration.k8s.io/v1"
RBAC = "rbac.authorization.k8s.io/v1"
NAMESPACE = "saf-gpu-a100"
OWNER = "fixture-response-reviewer"
VAP_MESSAGE = "A live accelerator signal for an approved fixture requires independent corroboration before escalation"


class AdmissionError(RuntimeError):
    pass


def names(runid):
    if not re.fullmatch(r"[0-9a-f]{8}", runid):
        raise AdmissionError("Expected an eight-digit fixture reference")
    return (f"fixture-decision-live-a100-{runid}", f"fixture-escalation-live-a100-{runid}",
            f"saf-a100-live-hold-{runid}")


def configure_identity(request, runid):
    policy = names(runid)[2]
    request("apply", "-f", "-", obj={"apiVersion": RBAC, "kind": "Role",
            "metadata": {"name": policy, "namespace": NAMESPACE},
            "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "create"]}]})
    request("apply", "-f", "-", obj={"apiVersion": RBAC, "kind": "RoleBinding",
            "metadata": {"name": policy, "namespace": NAMESPACE},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": policy},
            "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": OWNER}]})


def install(request, runid):
    hold, escalation, policy = names(runid)
    request("apply", "-f", "-", obj={"apiVersion": API, "kind": "ValidatingAdmissionPolicy",
            "metadata": {"name": policy}, "spec": {"failurePolicy": "Fail", "matchConstraints": {"resourceRules": [{
                "apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["configmaps"]}]},
                "matchConditions": [{"name": "owned-hold-and-escalation-only", "expression":
                                     f"object.metadata.name in ['{hold}', '{escalation}']"}],
                "validations": [{"expression": ("has(object.data) && 'disposition' in object.data && "
                     f"((object.metadata.name == '{hold}' && object.data.disposition == 'hold') || "
                     f"(object.metadata.name == '{escalation}' && object.data.disposition == 'escalate' && "
                     f"request.userInfo.username == '{OWNER}' && 'workload' in object.data && "
                     "object.data.workload == 'unapproved' && 'corroboration' in object.data && "
                     "object.data.corroboration == 'verified-independent'))"),
                     "message": VAP_MESSAGE}]}})
    request("apply", "-f", "-", obj={"apiVersion": API, "kind": "ValidatingAdmissionPolicyBinding",
            "metadata": {"name": policy}, "spec": {"policyName": policy, "validationActions": ["Deny"],
                "matchResources": {"namespaceSelector": {
                    "matchLabels": {"kubernetes.io/metadata.name": NAMESPACE}}}}})


def submit(request, record, *, persist_hold=False):
    options = () if persist_hold else ("--dry-run=server",)
    return request("--as", OWNER, "-n", NAMESPACE, "create", "-f", "-", "-o", "json", *options,
                   obj=record, allow_failure=True)


def escalation_for(hold, runid):
    escalation = deepcopy(hold)
    escalation["metadata"]["name"] = names(runid)[1]
    escalation["data"]["disposition"] = "escalate"
    escalation["data"]["corroboration"] = "missing"
    return escalation


def exact_denial(result, policy):
    signature = f"ValidatingAdmissionPolicy '{policy}' with binding '{policy}' denied request: {VAP_MESSAGE}"
    return result.returncode != 0 and signature in result.stderr


def establish_enforcement(request, runid, hold, escalation, *, timeout=25):
    """Use the request path as the readiness signal for the current binding."""
    policy = names(runid)[2]
    deadline = time.monotonic() + timeout
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        outcome = submit(request, escalation)
        if exact_denial(outcome, policy):
            allowed = submit(request, hold)
            if allowed.returncode != 0:
                raise AdmissionError("Effective policy did not admit the valid dry-run hold")
            return attempts
        if outcome.returncode != 0:
            raise AdmissionError("Unexpected API response while checking the exact escalation denial")
        time.sleep(0.25)
    raise AdmissionError("Expected policy and binding never denied the fixture escalation")


def retain_hold_and_check(request, runid, hold, escalation):
    hold_name, escalation_name, policy = names(runid)
    if (hold["metadata"] != {"name": hold_name, "namespace": NAMESPACE}
            or hold["immutable"] is not True or hold["data"]["disposition"] != "hold"):
        raise AdmissionError("Expected the exact immutable fixture hold")
    created = submit(request, hold, persist_hold=True)
    if created.returncode != 0:
        raise AdmissionError("The API did not retain the valid immutable hold")
    read = request("-n", NAMESPACE, "get", "configmap", hold_name, "-o", "json")
    stored = json.loads(read.stdout)
    meta = stored["metadata"]
    bound = (stored["immutable"] is True and bool(meta.get("uid")) and meta["name"] == hold_name
             and meta["namespace"] == NAMESPACE and stored["data"] == hold["data"])
    denied = exact_denial(submit(request, escalation), policy)
    missing = request("-n", NAMESPACE, "get", "configmap", escalation_name, "-o", "json", allow_failure=True)
    absent = (missing.returncode != 0 and "(NotFound)" in missing.stderr
              and f'configmaps "{escalation_name}" not found' in missing.stderr)
    return {"hold_immutable_and_receipt_bound": bound, "escalation_denied_by_policy": denied,
            "escalation_not_persisted": absent}
