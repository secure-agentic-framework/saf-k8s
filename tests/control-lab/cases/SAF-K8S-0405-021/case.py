"""Enforce two distinct approvals at a real named recovery authorization boundary."""
import importlib.util
import json
from pathlib import Path
import time

NS = "saf-test"
RBAC = "rbac.authorization.k8s.io/v1"
ADMISSION = "admissionregistration.k8s.io/v1"
GROUP = "rbac.authorization.k8s.io"
REQUEST = "fixture-activation-record"
CHANGE = "fixture-incident-001"
TARGET = "fixture-approved-data"
ACTIVATE = "fixture-recovery-bind"
APPROVERS = ("fixture-first-approver", "fixture-second-approver")
OPERATOR = "fixture-provisioner"
RECOVERY = "fixture-activated-reader"
APPROVAL_REJECTED = "record must be changed by its distinct authorized approver"
ACTIVATION_REJECTED = "two distinct recorded approvals and the exact recovery binding are required"
SCOPE = (
    "Native admission binds each approval to a distinct authenticated temporary caller, then "
    "requires the same scoped approval record at authorizing a named recovery RoleBinding. "
    "The actual Kubernetes API permits only the named ordinary read after approved activation. "
    "This tests the local authorization workflow and does not establish identity-provider "
    "MFA, operational independence or production authority paths."
)


def recovery_fixture():
    path = Path(__file__).resolve().parents[1] / "SAF-K8S-0405-020" / "case.py"
    spec = importlib.util.spec_from_file_location("saf_fixture_recovery", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def subject(name):
    return {"kind": "ServiceAccount", "name": name, "namespace": NS}


def username(name):
    return f"system:serviceaccount:{NS}:{name}"


def role(lab, fixture, name, rules, accounts=()):
    fixture.put(lab, "Role", name, RBAC, rules=rules)
    if accounts:
        fixture.put(lab, "RoleBinding", name, RBAC,
                    roleRef={"apiGroup": GROUP, "kind": "Role", "name": name},
                    subjects=[subject(account) for account in accounts])


def permission(group, resource, verbs, names=None):
    row = {"apiGroups": [group], "resources": [resource], "verbs": verbs}
    if names:
        row["resourceNames"] = names
    return row


def policy(lab, fixture, name, group, resource, operation, conditions, expression, message, parameters=False):
    match = {"resourceRules": [{"apiGroups": [group], "apiVersions": ["v1"],
                                "operations": [operation], "resources": [resource]}]}
    condition = [{"name": f"constraint-{index}", "expression": item} for index, item in enumerate(conditions)]
    spec = {"failurePolicy": "Fail", "matchConstraints": match, "matchConditions": condition,
            "validations": [{"expression": expression, "message": message}]}
    binding = {"policyName": name, "validationActions": ["Deny"]}
    if parameters:
        spec["paramKind"] = {"apiVersion": "v1", "kind": "ConfigMap"}
        binding["paramRef"] = {"name": REQUEST, "namespace": NS, "parameterNotFoundAction": "Deny"}
    fixture.put(lab, "ValidatingAdmissionPolicy", name, ADMISSION, spec=spec)
    fixture.put(lab, "ValidatingAdmissionPolicyBinding", name, ADMISSION, spec=binding)


def enforce(lab, fixture):
    left, right = map(username, APPROVERS)
    approval = (
        "object.data.size() == 3 && oldObject.data.change == object.data.change && ("
        f"(request.userInfo.username == '{left}' && oldObject.data.left == 'pending' "
        "&& object.data.left == request.userInfo.username && oldObject.data.right == object.data.right) || "
        f"(request.userInfo.username == '{right}' && oldObject.data.right == 'pending' "
        "&& object.data.right == request.userInfo.username && oldObject.data.left == object.data.left))"
    )
    policy(lab, fixture, "fixture-record-distinct-approval", "", "configmaps", "UPDATE",
           [f"request.namespace == '{NS}' && object.metadata.name == '{REQUEST}'"],
           approval, APPROVAL_REJECTED)
    activation = (
        f"params != null && params.data.change == '{CHANGE}' "
        f"&& params.data.left == '{left}' && params.data.right == '{right}' "
        f"&& object.metadata.name == '{ACTIVATE}' && object.roleRef.name == '{TARGET}' "
        f"&& object.roleRef.kind == 'Role' && object.roleRef.apiGroup == '{GROUP}' "
        f"&& object.subjects.size() == 1 && object.subjects[0].kind == 'ServiceAccount' "
        f"&& object.subjects[0].name == '{RECOVERY}' && object.subjects[0].namespace == '{NS}'"
    )
    policy(lab, fixture, "fixture-require-paired-approval", GROUP, "rolebindings", "CREATE",
           [f"request.namespace == '{NS}' && request.userInfo.username == '{username(OPERATOR)}'"],
           activation, ACTIVATION_REJECTED, parameters=True)


def owned_call(lab, profile, *args, payload=None):
    return lab.command("kubectl", "--kubeconfig", str(profile), "--context", "fixture",
                       "--namespace", NS, "--request-timeout=7s", *args,
                       payload=payload, timeout=14, allow_failure=True)


def activate(lab, profile, name=ACTIVATE, dry=False):
    path = f"/apis/{GROUP}/v1/namespaces/{NS}/rolebindings" + ("?dryRun=All" if dry else "")
    body = {"apiVersion": RBAC, "kind": "RoleBinding", "metadata": {"name": name},
            "roleRef": {"apiGroup": GROUP, "kind": "Role", "name": TARGET},
            "subjects": [subject(RECOVERY)]}
    return owned_call(lab, profile, "create", "--raw="+path, "-f", "-", payload=json.dumps(body))


def approve(lab, profile, dry=False, **changes):
    return owned_call(lab, profile, "patch", "configmap", REQUEST, "--type=merge",
                      "-p", json.dumps({"data": changes}), "-o", "name",
                      *(("--dry-run=server",) if dry else ()))


def wait_for(action, predicate):
    for _ in range(12):
        observation = action()
        if predicate(observation):
            break
        time.sleep(.5)
    return observation


def run(lab):
    fixture = recovery_fixture()
    for name in (*APPROVERS, RECOVERY, OPERATOR):
        fixture.put(lab, "ServiceAccount", name, automountServiceAccountToken=False)
    fixture.put(lab, "ConfigMap", TARGET, data={"marker": fixture.MARKER})
    fixture.put(lab, "ConfigMap", REQUEST, data={"change": CHANGE, "left": "pending", "right": "pending"})
    role(lab, fixture, TARGET, [permission("", "configmaps", ["get"], [TARGET])])
    role(lab, fixture, "fixture-record-approver", [permission("", "configmaps", ["get", "patch"], [REQUEST])],
         APPROVERS)
    role(lab, fixture, "fixture-record-provisioner", [
        permission("", "configmaps", ["get"], [REQUEST]),
        permission(GROUP, "roles", ["bind"], [TARGET]),
        permission(GROUP, "rolebindings", ["create"]),
    ], [OPERATOR])
    left, right, operator, reader = (
        fixture.identity(lab, name, f"approval-{name}") for name in (*APPROVERS, OPERATOR, RECOVERY)
    )
    initial = activate(lab, operator)
    baseline = {"actual_grant_created_without_approval_gate": initial.returncode == 0,
                "ungated_fixture_access_effective": wait_for(lambda: fixture.read(lab, reader, TARGET), lambda status: status == "allowed") == "allowed"}
    lab.check("red", "A grant can become effective before the explicit approval control is applied",
              all(baseline.values()), baseline)
    lab.kubectl("delete", "rolebinding", ACTIVATE, "--wait=true")
    enforce(lab, fixture)

    waiting = wait_for(lambda: activate(lab, operator, dry=True), lambda result: ACTIVATION_REJECTED in result.stderr)
    if ACTIVATION_REJECTED not in waiting.stderr:
        lab.block("The selected activation admission policy did not become effective")
    policy_ready = wait_for(lambda: approve(lab, left, dry=True, right=username(APPROVERS[1])),
                            lambda result: APPROVAL_REJECTED in result.stderr)
    if APPROVAL_REJECTED not in policy_ready.stderr:
        lab.block("The selected approver attribution policy did not become effective")
    first = approve(lab, left, left=username(APPROVERS[0]))
    duplicate = approve(lab, left, right=username(APPROVERS[1]))
    denied = activate(lab, operator, dry=True)
    governed = {"first_actor_can_record_its_own_approval": first.returncode == 0,
                "same_actor_cannot_record_other_approval": APPROVAL_REJECTED in duplicate.stderr,
                "single_approval_does_not_activate": ACTIVATION_REJECTED in denied.stderr,
                "recovery_access_remains_unavailable": wait_for(lambda: fixture.read(lab, reader, TARGET), lambda status: status == "forbidden") == "forbidden"}
    lab.check("green", "Admission binds approval to the real caller and denies single-actor activation",
              all(governed.values()), governed)

    second = approve(lab, right, right=username(APPROVERS[1]))
    ready = wait_for(lambda: activate(lab, operator, dry=True), lambda result: result.returncode == 0)
    activation = activate(lab, operator) if ready.returncode == 0 else ready
    different = activate(lab, operator, name="fixture-other-binding", dry=True)
    final = {"independent_approval_accepted": second.returncode == 0,
             "only_exact_activation_is_permitted": activation.returncode == 0 and ACTIVATION_REJECTED in different.stderr,
             "approved_recovery_read_effective": wait_for(lambda: fixture.read(lab, reader, TARGET), lambda status: status == "allowed") == "allowed",
             "approval_record_remains_separately_protected": fixture.read(lab, reader, REQUEST) == "forbidden"}
    lab.check("positive", "The second scoped approval enables only the intended fixture read",
              all(final.values()), final)
    (lab.evidence / "multi-party-approval-observations.json").write_text(json.dumps({
        "baseline": baseline, "enforced": governed, "authorized": final,
    }, indent=2) + "\n")
