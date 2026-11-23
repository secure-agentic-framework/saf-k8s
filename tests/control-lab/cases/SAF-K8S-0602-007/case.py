"""Check authorization and immutability for an inert approval record."""
import json
import time

NS = "saf-test"
RECORD = "saf-0602-007-review"
POLICY = "saf-0602-007-record-integrity"
RBAC_API = "rbac.authorization.k8s.io/v1"
ADMISSION_API = "admissionregistration.k8s.io/v1"
REVIEWERS = {"saf-security": "security", "saf-operations": "operations"}
READER = "saf-requester"
MESSAGE = "only the designated reviewer can approve its own field on this exact record"
SCOPE = (
    "One disposable Kind cluster. RBAC and native admission restrict an inert ConfigMap "
    "containing a synthetic review request, exact SHA-256 digest, and fixed approval window. "
    "The example preserves separate actor identities and refuses excess privileges and changes "
    "to signed-off request fields. The record has no link to image admission or workload execution. "
    "Production approval, audit delivery, trusted time and lifecycle need separate evidence."
)


def object_spec(api, kind, name, **fields):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields}


def grant(lab, name, actors, verbs):
    rules = [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [RECORD],
              "verbs": verbs}]
    lab.create(object_spec(RBAC_API, "Role", name, rules=rules))
    lab.create(object_spec(RBAC_API, "RoleBinding", name, roleRef={
        "apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name,
    }, subjects=[{"kind": "ServiceAccount", "name": actor, "namespace": NS} for actor in actors]))


def user(actor):
    return f"system:serviceaccount:{NS}:{actor}"


def install_guard(lab):
    choices = []
    for reviewer, own_vote in REVIEWERS.items():
        other_vote, = (vote for vote in REVIEWERS.values() if vote != own_vote)
        choices.append(f"(request.userInfo.username == '{user(reviewer)}' "
                       f"&& oldObject.data['{own_vote}'] == 'pending' "
                       f"&& object.data['{own_vote}'] == 'approved' "
                       f"&& object.data['{other_vote}'] == oldObject.data['{other_vote}'])")
    immutable = " && ".join(
        f"object.data['{name}'] == oldObject.data['{name}']"
        for name in ("requestId", "targetDigest", "expiresAt")
    )
    policy = object_spec(ADMISSION_API, "ValidatingAdmissionPolicy", POLICY, spec={
        "failurePolicy": "Fail",
        "matchConstraints": {"resourceRules": [{
            "apiGroups": [""], "apiVersions": ["v1"], "operations": ["UPDATE"],
            "resources": ["configmaps"],
        }]},
        "matchConditions": [{"name": "owned-record", "expression":
                             f"request.namespace == '{NS}' && request.name == '{RECORD}'"}],
        "validations": [{"expression": f"size(object.data) == 5 && {immutable} && ({' || '.join(choices)})",
                         "message": MESSAGE, "reason": "Forbidden"}],
    })
    lab.create(policy)
    lab.create(object_spec(ADMISSION_API, "ValidatingAdmissionPolicyBinding", POLICY,
                           spec={"policyName": POLICY, "validationActions": ["Deny", "Audit"]}))


def modify(lab, actor, values, *, dry=False):
    flags = ["--dry-run=server"] if dry else []
    return lab.kubectl(f"--as={user(actor)}", "patch", "configmap", RECORD, "--type=merge",
                       "-p", json.dumps({"data": values}), *flags, "-o", "json", allow_failure=True)


def policy_rejected(result):
    return result.returncode != 0 and POLICY in result.stderr and MESSAGE in result.stderr


def run(lab):
    original = {"requestId": "saf-0602-007-synthetic-request", "targetDigest": "sha256:" + "a" * 64,
                "expiresAt": "2032-01-01T00:15:00Z", "security": "pending", "operations": "pending"}
    for actor in (*REVIEWERS, READER):
        lab.create(object_spec("v1", "ServiceAccount", actor))
    lab.create(object_spec("v1", "ConfigMap", RECORD, data=original))
    grant(lab, "saf-0602-007-reviewer", REVIEWERS, ["get", "patch"])
    grant(lab, "saf-0602-007-request-read", [READER], ["get"])

    cross_vote = {"operations": "approved"}
    plain = modify(lab, "saf-security", cross_vote, dry=True)
    lab.check("red", "RBAC alone permits a reviewer to edit the other review in this record",
              plain.returncode == 0 and json.loads(plain.stdout)["data"]["operations"] == "approved",
              {"baseline_cross_vote_admitted_by_dry_run": plain.returncode == 0})

    install_guard(lab)
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        denied = modify(lab, "saf-security", cross_vote, dry=True)
        if policy_rejected(denied):
            break
        time.sleep(0.5)
    lab.check("green", "The admission policy denies a reviewer's cross-vote",
              policy_rejected(denied), {"cross_vote_denied": policy_rejected(denied)})

    req = modify(lab, READER, {"security": "approved"}, dry=True)
    denied_by_rbac = (req.returncode != 0 and "cannot patch resource" in req.stderr and user(READER) in req.stderr)
    lab.check("green", "The requester has read access and cannot approve their own record",
              denied_by_rbac and lab.kubectl(f"--as={user(READER)}", "get", "configmap", RECORD,
                                            allow_failure=True).returncode == 0,
              {"requester_write_denied_by_rbac": denied_by_rbac})

    for field, replacement in (("targetDigest", "sha256:" + "b" * 64),
                               ("expiresAt", "2032-01-01T01:15:00Z"), ("requestId", "other-request")):
        altered = modify(lab, "saf-security", {"security": "approved", field: replacement}, dry=True)
        lab.check("green", f"Approval cannot change the record's {field}",
                  policy_rejected(altered), {"field": field, "mutation_denied": policy_rejected(altered)})

    first = modify(lab, "saf-security", {"security": "approved"})
    second = modify(lab, "saf-operations", {"operations": "approved"})
    reader = lab.kubectl(f"--as={user(READER)}", "get", "configmap", RECORD, "-o", "json")
    verified = json.loads(reader.stdout)["data"] == {**original, "security": "approved", "operations": "approved"}
    lab.check("positive", "Two independent reviewers can record votes on the same exact request",
              first.returncode == second.returncode == 0 and verified,
              {"separate_approvals_persisted": verified})
    pod_permission = lab.kubectl(f"--as={user(READER)}", "auth", "can-i", "create", "pods", allow_failure=True)
    lab.check("positive", "The inert record confers no Pod-create permission on the requester",
              pod_permission.stdout.strip() == "no", {"requester_can_create_pods": False})
