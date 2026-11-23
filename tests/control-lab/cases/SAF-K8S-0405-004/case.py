"""Exercise a role provisioning gate driven by reviewed fictional training records."""
from datetime import datetime, timedelta, timezone
import json
import time

RBAC = "rbac.authorization.k8s.io/v1"
ADMISSION = "admissionregistration.k8s.io/v1"
NS = "saf-test"
ROLE = "fixture-gpu-quota-reader"
ACTOR = "fixture-operator"
OTHER = "fixture-unlisted-operator"
RECORD = "fixture-training-registry"
POLICY = "fixture-training-provisioning"
QUOTA = "fixture-gpu-quota"
DENIAL = "Current approved role training is required for the governed fixture grant"
SCOPE = (
    "Controlled training records gate a real Kubernetes RoleBinding with rights to read "
    "a synthetic ResourceQuota. The test covers pending and overdue records, "
    "provenance and distinct role scope. Training delivery, human competence and operating "
    "effectiveness require evidence from the applicable organization."
)


def object_of(lab, kind, name, *, api="v1", **fields):
    return lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields})


def grant(lab, operator, name, *, dry_run=False):
    return lab.create({"apiVersion": RBAC, "kind": "RoleBinding", "metadata": {"name": name},
                       "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": ROLE},
                       "subjects": [{"kind": "ServiceAccount", "name": operator, "namespace": NS}]},
                      dry_run=dry_run, allow_failure=True)


def read_quota(lab, actor):
    return lab.kubectl("--as=" + f"system:serviceaccount:{NS}:{actor}", "get", "resourcequota", QUOTA,
                       "-o", "name", allow_failure=True)


def was_denied(result):
    return result.returncode != 0 and DENIAL in result.stderr


def until(probe, expected):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if expected(probe()):
            return True
        time.sleep(.5)
    return False


def check_provisioning(lab):
    lab.kubectl("label", "namespace", NS, "saf-k8s.example/training-fixture=governed")
    validation = (
        f"object.roleRef.name != '{ROLE}' || "
        "(params != null && has(params.data) && "
        "['activity','operator','decision','verifiedBy','expiresAt'].all(k, k in params.data && size(params.data[k]) > 0)"
        " && params.data.activity == 'fixture-k8s-role-exercise' && params.data.decision == 'current'"
        " && params.data.verifiedBy == 'fixture-training-reviewer'"
        " && size(object.subjects) == 1 && object.subjects.all(s, s.kind == 'ServiceAccount'"
        " && s.name == params.data.operator && s.namespace == request.namespace))"
    )
    object_of(lab, "ValidatingAdmissionPolicy", POLICY, api=ADMISSION, spec={
        "failurePolicy": "Fail", "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
        "matchConstraints": {"resourceRules": [{
            "apiGroups": ["rbac.authorization.k8s.io"], "apiVersions": ["v1"], "operations": ["CREATE"],
            "resources": ["rolebindings"]}]},
        "validations": [{"expression": validation, "message": DENIAL}],
    })
    object_of(lab, "ValidatingAdmissionPolicyBinding", POLICY, api=ADMISSION, spec={
        "policyName": POLICY, "validationActions": ["Deny"],
        "paramRef": {"name": RECORD, "namespace": NS, "parameterNotFoundAction": "Deny"},
        "matchResources": {
            "namespaceSelector": {"matchLabels": {"saf-k8s.example/training-fixture": "governed"}}},
    })


def write_review(lab, data, now):
    accepted = (data.get("exercise") == "reviewed-pass"
                and datetime.fromisoformat(data["expiresAt"]) > now)
    record = {**data, "decision": "current" if accepted else "overdue-or-incomplete"}
    lab.kubectl("patch", "configmap", RECORD, "--type=merge", "-p", json.dumps({"data": record}), "-o", "name")
    return record["decision"]


def run(lab):
    for actor in (ACTOR, OTHER):
        object_of(lab, "ServiceAccount", actor, automountServiceAccountToken=False)
    object_of(lab, "ResourceQuota", QUOTA, spec={"hard": {"requests.nvidia.com/gpu": "1"}})
    object_of(lab, "Role", ROLE, api=RBAC, rules=[
        {"apiGroups": [""], "resources": ["resourcequotas"], "resourceNames": [QUOTA], "verbs": ["get"]}])
    object_of(lab, "ConfigMap", RECORD, data={"decision": "pending"})
    allowed = grant(lab, ACTOR, "fixture-without-training")
    initial = allowed.returncode == 0 and until(lambda: read_quota(lab, ACTOR), lambda r: r.returncode == 0)
    lab.check("red", "Without the training gate the requested RoleBinding grants real scoped access",
              initial, {"unreviewed_access_exists_without_policy": initial})
    lab.kubectl("delete", "rolebinding", "fixture-without-training", "--wait=true")

    check_provisioning(lab)
    pending = until(lambda: grant(lab, ACTOR, "fixture-training-pending", dry_run=True), was_denied)
    now = datetime.now(timezone.utc)
    data = {
        "activity": "fixture-k8s-role-exercise", "operator": ACTOR, "verifiedBy": "fixture-training-reviewer",
        "exercise": "reviewed-pass", "expiresAt": (now + timedelta(days=1)).isoformat(),
    }
    completion = write_review(lab, data, now)
    active = until(lambda: grant(lab, ACTOR, "fixture-approved-training", dry_run=True), lambda r: r.returncode == 0)
    actual = active and grant(lab, ACTOR, "fixture-approved-training").returncode == 0
    other_denied = was_denied(grant(lab, OTHER, "fixture-other", dry_run=True))
    review = {"pending_record_denied": pending, "current_record_allows_desired_grant": completion == "current" and actual,
              "unlisted_subject_denied": other_denied,
              "scoped_quota_api_access_observed": until(lambda: read_quota(lab, ACTOR), lambda r: r.returncode == 0)}
    lab.check("green", "A current reviewed training record permits only its exact scoped grant",
              all(review.values()), review)

    expired = write_review(lab, data, now + timedelta(days=2)) == "overdue-or-incomplete"
    prevents_new = until(lambda: grant(lab, ACTOR, "fixture-overdue-training", dry_run=True), was_denied)
    existing = read_quota(lab, ACTOR).returncode == 0
    lab.kubectl("delete", "rolebinding", "fixture-approved-training", "--wait=true")
    suspended = until(lambda: read_quota(lab, ACTOR),
                      lambda r: r.returncode != 0 and "(Forbidden)" in r.stderr)
    follow = {"overdue_record_prevents_new_grant": expired and prevents_new,
              "previously_granted_access_needs_separate_action": existing and suspended}
    lab.check("positive", "An overdue review closes new provisioning and a separate action retires existing access",
              all(follow.values()), follow)
    (lab.evidence/"role-training-observations.json").write_text(json.dumps({
        "unreviewed_access_without_policy": initial, "training_review": review, "overdue_response": follow,
    },indent=2)+"\n")
