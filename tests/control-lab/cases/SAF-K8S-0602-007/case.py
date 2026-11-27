"""Check authorization and immutability for an inert approval record."""
import json
import hashlib
import subprocess
import sys
import time
from pathlib import Path

NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)

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
    "to signed-off request fields. A local Kubernetes audit log is scoped to ConfigMap patch/update "
    "requests in the sole fixture namespace and correlates the exact approval record, denial, and votes. "
    "The record has no link to image admission or workload execution. Remote audit delivery/retention, "
    "human approval, trusted time, and the deployed lifecycle need separate evidence."
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


def run_expiry_reference(lab):
    """Exercise a separate time-aware consumer with the persisted inert approval record."""
    expected_record = {
        "requestId": "saf-0602-007-synthetic-request",
        "targetDigest": "sha256:" + "a" * 64,
        "expiresAt": "2032-01-01T00:15:00Z",
        "security": "approved",
        "operations": "approved",
    }
    before_obj = json.loads(lab.kubectl(
        "get", "configmap", RECORD, "-n", NS, "-o", "json").stdout)
    record = before_obj.get("data", {})
    if record != expected_record:
        lab.block("The persisted approved record did not match the exact inert fixture")
    request = {"requestId": record["requestId"], "targetDigest": record["targetDigest"]}
    payloads = {
        "current": {"record": record, "request": request,
                    "evaluatedAt": "2032-01-01T00:14:59Z"},
        "expired": {"record": record, "request": request,
                    "evaluatedAt": "2032-01-01T00:15:00Z"},
        "wrong_request": {"record": record,
                           "request": {"requestId": "other-synthetic-request",
                                       "targetDigest": record["targetDigest"]},
                           "evaluatedAt": "2032-01-01T00:14:59Z"},
    }
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    original_fingerprint = hashlib.sha256(canonical).hexdigest()
    results = {}
    consumer = Path(__file__).with_name("expiry_consumer.py")
    for case, payload in payloads.items():
        result = subprocess.run(
            [sys.executable, str(consumer)], input=json.dumps(payload), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=False)
        if result.returncode != 0:
            lab.block("The isolated expiry decision consumer did not return a verdict")
        try:
            results[case] = json.loads(result.stdout)
        except (ValueError, TypeError):
            lab.block("The isolated expiry decision consumer returned an invalid verdict")
    after_obj = json.loads(lab.kubectl(
        "get", "configmap", RECORD, "-n", NS, "-o", "json").stdout)
    after_record = after_obj.get("data", {})
    unchanged = (
        hashlib.sha256(json.dumps(after_record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        == original_fingerprint and after_record == record
    )
    current_allowed = results["current"] == {"permitted": True, "reason": "approved-unexpired"}
    expired_denied = results["expired"] == {"permitted": False, "reason": "expired"}
    wrong_request_denied = results["wrong_request"] == {
        "permitted": False, "reason": "request-mismatch"}
    passed = unchanged and current_allowed and expired_denied and wrong_request_denied
    lab.check(
        "positive",
        "A separate bounded consumer allows the exact current approval and denies it at expiry",
        passed,
        {"fixture_record_unchanged": unchanged,
         "exact_current_request_permitted": current_allowed,
         "expired_request_denied": expired_denied,
         "different_request_denied": wrong_request_denied,
         "time_source": "fixed-fixture-input",
         "enforcement_boundary": "application-reference-only"})
    (lab.evidence / "expiry-reference-observations.json").write_text(json.dumps({
        "fixture_record_unchanged": unchanged,
        "exact_current_request_permitted": current_allowed,
        "expired_request_denied": expired_denied,
        "different_request_denied": wrong_request_denied,
        "time_source": "fixed-fixture-input",
        "enforcement_boundary": "application-reference-only",
    }, sort_keys=True, indent=2) + "\n")


_published_run = run


def run(lab):
    _published_run(lab)
    run_expiry_reference(lab)


_expiry_run = run


def run(lab):
    _expiry_run(lab)
    from importlib.util import module_from_spec, spec_from_file_location

    revocation_spec = spec_from_file_location(
        "saf_0602_007_revocation_lifecycle",
        Path(__file__).with_name("revocation_lifecycle.py"))
    revocation = module_from_spec(revocation_spec)
    revocation_spec.loader.exec_module(revocation)
    revocation.run(lab, Path(__file__).parent)


def _audit_correlation_module():
    from importlib.util import module_from_spec, spec_from_file_location

    path = Path(__file__).with_name("audit_correlation.py")
    spec = spec_from_file_location("saf_0602_007_audit_correlation", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("The bounded approval audit fixture is unavailable")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare_kind(lab, temporary):
    return _audit_correlation_module().prepare_kind(lab, temporary)


_run_with_revocation = run


def run(lab):
    _run_with_revocation(lab)
    _audit_correlation_module().run(lab)
