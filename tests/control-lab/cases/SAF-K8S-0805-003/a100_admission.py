"""Exercise the admission boundary for the disposable A100 diagnostic."""

from copy import deepcopy
from hashlib import sha256
import json
import re
import time

API = "admissionregistration.k8s.io/v1"
RBAC = "rbac.authorization.k8s.io/v1"
NAMESPACE = "saf-gpu-a100"
OWNER = "fixture-response-reviewer"
APPROVER = "fixture-independent-approver"
APPROVAL = "independent-corroboration"
BOUND_KEYS = ("capture_ref", "hold_name", "workload_ref", "device_ref", "receipt_sha256")
VAP_MESSAGE = "Escalation requires separately authorized corroboration bound to the exact fixture decision"


class AdmissionError(RuntimeError):
    pass


def names(runid):
    if not re.fullmatch(r"[0-9a-f]{8}", runid):
        raise AdmissionError("Expected an eight-digit fixture reference")
    return (f"fixture-decision-live-a100-{runid}", f"fixture-escalation-live-a100-{runid}",
            f"saf-a100-live-hold-{runid}")


def approval_namespace(runid):
    names(runid)
    return "saf-a100-approval-" + runid


class OwnedResources:
    """Clean up only API-created resources whose UIDs still match."""

    def __init__(self, request):
        self.request = request
        self.created = []

    def __enter__(self):
        return self

    def create(self, obj, actor=None):
        meta = obj["metadata"]
        scope = ("-n", meta["namespace"]) if "namespace" in meta else ()
        auth = ("--as", actor) if actor else ()
        result = self.request(*scope, *auth, "create", "-f", "-", "-o", "json", obj=obj)
        created = json.loads(result.stdout)
        self.created.append((scope, obj["kind"].lower(), meta["name"], created["metadata"]["uid"]))
        return created

    def __exit__(self, *_):
        errors = []
        for scope, kind, name, uid in reversed(self.created):
            try:
                outcome = self.request(*scope, "get", kind, name, "--ignore-not-found", "-o", "json")
                if not outcome.stdout.strip():
                    continue
                actual = json.loads(outcome.stdout)
                if actual["metadata"]["uid"] != uid:
                    raise AdmissionError(f"Refusing to delete replaced fixture {kind}/{name}")
                self.request(*scope, "delete", kind, name, "--wait=true", "--timeout=40s", timeout=45)
            except Exception as exc:
                errors.append(str(exc))
        if errors:
            raise AdmissionError("Fixture cleanup incomplete: " + "; ".join(errors))


def grant(owned, namespace, name, user, rules):
    owned.create({"apiVersion": RBAC, "kind": "Role", "metadata": {"name": name, "namespace": namespace},
                  "rules": rules})
    owned.create({"apiVersion": RBAC, "kind": "RoleBinding", "metadata": {"name": name, "namespace": namespace},
                  "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name},
                  "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": user}]})


def configure_identity(owned, runid):
    ns = approval_namespace(runid)
    owned.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns}})
    grant(owned, NAMESPACE, names(runid)[2], OWNER,
          [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["create"]}])
    grant(owned, ns, "independent-corroborator", APPROVER,
          [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["create"]}])
    grant(owned, ns, "corroboration-reader", OWNER,
          [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [APPROVAL], "verbs": ["get"]}])


def wait_for_roles(request, runid):
    ns = approval_namespace(runid)
    checks = ((OWNER, NAMESPACE, "create", "configmaps"), (APPROVER, ns, "create", "configmaps"),
              (OWNER, ns, "get", f"configmap/{APPROVAL}"))
    deadline = time.monotonic() + 12
    for user, namespace, verb, target in checks:
        while time.monotonic() < deadline:
            outcome = request("--as", user, "-n", namespace, "auth", "can-i", verb, target, allow_failure=True)
            if outcome.returncode == 0 and outcome.stdout.strip() == "yes":
                break
            time.sleep(0.25)
        else:
            raise AdmissionError("The exact reviewer and corroborator roles did not become available")


def comparator_data(runid):
    # Dedicated inert comparator, separate from the real or historical signal.
    return {"capture_ref": runid, "hold_name": names(runid)[0],
            "workload_ref": sha256(("inert-comparator-workload:" + runid).encode()).hexdigest(),
            "device_ref": sha256(("inert-comparator-device:" + runid).encode()).hexdigest(),
            "receipt_sha256": sha256(("inert-comparator-review:" + runid).encode()).hexdigest()}


def api_error(result, reason, message):
    pattern = rf'Error from server \({reason}\): (?:error when creating "STDIN": )?' + re.escape(message)
    return result.returncode != 0 and any(re.fullmatch(pattern, line.strip()) for line in result.stderr.splitlines())


def create_approval(request, owned, runid):
    ns = approval_namespace(runid)
    approval = {"apiVersion": "v1", "kind": "ConfigMap", "immutable": True,
                "metadata": {"name": APPROVAL, "namespace": ns},
                "data": {**comparator_data(runid), "approved_by": APPROVER, "authorized_reviewer": OWNER}}
    denied = request("--as", OWNER, "-n", ns, "create", "-f", "-", "--dry-run=server", obj=approval,
                     allow_failure=True)
    if not api_error(denied, "Forbidden",
                     f'configmaps is forbidden: User "{OWNER}" cannot create resource "configmaps" '
                     f'in API group "" in the namespace "{ns}"'):
        raise AdmissionError("Unexpected response to reviewer approval creation: " + denied.stderr.strip())
    created = owned.create(approval, actor=APPROVER)
    stored = json.loads(request("-n", ns, "get", "configmap", APPROVAL, "-o", "json").stdout)
    if (stored["metadata"]["uid"] != created["metadata"]["uid"]
            or stored["immutable"] is not True or stored["data"] != approval["data"]):
        raise AdmissionError("Independent approval readback differs from the exact created record")
    denied_update = request("--as", OWNER, "-n", ns, "patch", "configmap", APPROVAL,
                            "--type=merge", "-p", '{"data":{"approved_by":"reviewer"}}', "--dry-run=server",
                            allow_failure=True)
    if not api_error(denied_update, "Forbidden",
                     f'configmaps "{APPROVAL}" is forbidden: User "{OWNER}" cannot patch resource "configmaps" '
                     f'in API group "" in the namespace "{ns}"'):
        raise AdmissionError("Unexpected response to reviewer approval update: " + denied_update.stderr.strip())
    return sha256(json.dumps(stored["data"], sort_keys=True).encode()).hexdigest()


def install(owned, runid):
    hold, escalation, policy = names(runid)
    checks = " && ".join(f"'{key}' in object.data && '{key}' in params.data && object.data['{key}'] == params.data['{key}']"
                         for key in BOUND_KEYS)
    validated = ("has(object.data) && 'disposition' in object.data && has(object.immutable) && object.immutable && "
                 f"request.userInfo.username == '{OWNER}' && "
                 f"((object.metadata.name == '{hold}' && object.data.disposition == 'hold') || "
                 f"(object.metadata.name == '{escalation}' && object.data.disposition == 'escalate' && "
                 "'workload' in object.data && object.data.workload == 'unapproved' && "
                 "'corroboration' in object.data && object.data.corroboration == 'verified-independent' && "
                 "params != null && has(params.immutable) && params.immutable && has(params.data) && "
                 f"params.data.approved_by == '{APPROVER}' && params.data.authorized_reviewer == '{OWNER}' && "
                 f"params.data.capture_ref == '{runid}' && params.data.hold_name == '{hold}' && {checks}))")
    owned.create({"apiVersion": API, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": policy},
                  "spec": {"failurePolicy": "Fail", "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
                           "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                                  "operations": ["CREATE"], "resources": ["configmaps"]}]},
                           "matchConditions": [{"name": "owned-hold-and-escalation-only", "expression":
                                                f"object.metadata.name in ['{hold}', '{escalation}']"}],
                           "validations": [{"expression": validated, "message": VAP_MESSAGE, "reason": "Forbidden"}]}})
    owned.create({"apiVersion": API, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": policy},
                  "spec": {"policyName": policy, "validationActions": ["Deny"],
                           "paramRef": {"name": APPROVAL, "namespace": approval_namespace(runid),
                                        "parameterNotFoundAction": "Deny"},
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


def exact_denial(result, runid):
    _, escalation, policy = names(runid)
    decision = f"ValidatingAdmissionPolicy '{policy}' with binding '{policy}' denied request: {VAP_MESSAGE}"
    return any(api_error(result, "Forbidden", f'configmaps "{escalation}" is forbidden: {space}{decision}')
               for space in ("", ": "))


def establish_enforcement(request, runid, hold, escalation, *, timeout=25):
    """Use the request path as the readiness signal for the current binding."""
    deadline = time.monotonic() + timeout
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        outcome = submit(request, escalation)
        if exact_denial(outcome, runid):
            allowed = submit(request, hold)
            if allowed.returncode != 0:
                raise AdmissionError("Effective policy did not admit the valid dry-run hold")
            return attempts
        if outcome.returncode != 0:
            raise AdmissionError("Unexpected API response while checking escalation denial: " + outcome.stderr.strip())
        time.sleep(0.25)
    raise AdmissionError("Expected policy and binding never denied the fixture escalation")


def absent_escalation(request, runid):
    name = names(runid)[1]
    missing = request("-n", NAMESPACE, "get", "configmap", name, "-o", "json", allow_failure=True)
    return api_error(missing, "NotFound", f'configmaps "{name}" not found')


def retain_hold_and_check(request, runid, hold, escalation):
    hold_name = names(runid)[0]
    if (hold["metadata"] != {"name": hold_name, "namespace": NAMESPACE}
            or hold["immutable"] is not True or hold["data"]["disposition"] != "hold"):
        raise AdmissionError("Expected the exact immutable fixture hold")
    created = submit(request, hold, persist_hold=True)
    if created.returncode != 0:
        raise AdmissionError("The API did not retain the valid immutable hold")
    read = request("-n", NAMESPACE, "get", "configmap", hold_name, "-o", "json")
    stored = json.loads(read.stdout)
    meta = stored["metadata"]
    bound = (stored["immutable"] is True and meta["uid"] == json.loads(created.stdout)["metadata"]["uid"]
             and meta["name"] == hold_name and meta["namespace"] == NAMESPACE and stored["data"] == hold["data"])
    return {"hold_immutable_and_receipt_bound": bound,
            "escalation_denied_by_policy": exact_denial(submit(request, escalation), runid),
            "escalation_not_persisted": absent_escalation(request, runid)}


def verify_corroboration(request, runid, hold):
    self_asserted = escalation_for(hold, runid)
    self_asserted["data"].update(workload="unapproved", corroboration="verified-independent")
    comparator = deepcopy(self_asserted)
    comparator["data"].update(comparator_data(runid))
    crossed = {}
    for key in BOUND_KEYS:
        wrong = deepcopy(comparator)
        wrong["data"][key] = "different-" + wrong["data"][key]
        crossed[key] = exact_denial(submit(request, wrong), runid)
    return {"self_asserted_corroboration_denied": exact_denial(submit(request, self_asserted), runid),
            "all_wrong_approval_bindings_denied": all(crossed.values()),
            "corroborated_comparator_admitted_in_dry_run": submit(request, comparator).returncode == 0,
            "comparator_remained_absent": absent_escalation(request, runid)}
