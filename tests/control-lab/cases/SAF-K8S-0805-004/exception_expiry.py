"""Check the placement exception at its live admission consumer."""

from datetime import timedelta
from hashlib import sha256
import json
from pathlib import Path
import runpy
import time

HERE = Path(__file__).resolve().parent
RUNTIME_HELPER = HERE.parent / "SAF-K8S-1006-010" / "runtime_expiry.py"
RUNTIME_SHA = "3508af7a3819696a57c230e119d3ed943fe26c8ecc2cc5bfd613f6b53af7a94b"
NS = "saf-test"
APPROVER = "fixture-accelerator-approver"
REQUESTER = "fixture-sensitive-owner"
ROUTINE = "fixture-routine-owner"
WORKLOAD = "fixture-shared-exception"
RECORD = "fixture-accelerator-exception"
POLICY = "fixture-accelerator-exception-expiry"
LABEL = "fixture.example/accelerator-exception"
PROFILE = "fixture.example/accelerator-profile"
MISSING = "SAF-0805-004 approved placement exception is missing"
EXPIRED = "SAF-0805-004 placement exception expired"
EXPIRY_SECONDS = 25

PLACEMENT_REQUIREMENT = (
    f"request.userInfo.username == '{REQUESTER}' && "
    f"object.metadata.name == '{WORKLOAD}' && "
    f"object.spec.nodeSelector['{PROFILE}'] == 'shared' && "
    f"has(object.metadata.labels) && '{LABEL}' in object.metadata.labels && "
    f"object.metadata.labels['{LABEL}'] == '{RECORD}'"
)


def matches_label():
    return (f"object.metadata.namespace == '{NS}' && has(object.metadata.labels) && "
            f"'{LABEL}' in object.metadata.labels && object.metadata.labels['{LABEL}'] == '{RECORD}'")


def create_scope(lab, consumer_account):
    rbac = "rbac.authorization.k8s.io/v1"
    for identity, kind, rules in (
        (APPROVER, "User", [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["create"]}]),
        (consumer_account, "ServiceAccount", [
            {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [RECORD], "verbs": ["get"]}]),
    ):
        name = f"{POLICY}-{kind.lower()}"
        subject = {"kind": kind, "name": identity}
        if kind == "ServiceAccount":
            subject["namespace"] = "kyverno"
        else:
            subject["apiGroup"] = "rbac.authorization.k8s.io"
        lab.create({"apiVersion": rbac, "kind": "Role", "metadata": {"name": name}, "rules": rules})
        lab.create({"apiVersion": rbac, "kind": "RoleBinding", "metadata": {"name": name},
                    "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name},
                    "subjects": [subject]})


def approval_policy(lab):
    api = "admissionregistration.k8s.io/v1"
    name = f"{POLICY}-issuer"
    validation = (
        f"request.userInfo.username == '{APPROVER}' && has(object.immutable) && object.immutable && "
        f"has(object.data) && 'approver' in object.data && object.data['approver'] == '{APPROVER}'"
    )
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": name},
                "spec": {"failurePolicy": "Fail", "matchConstraints": {"resourceRules": [{
                    "apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["configmaps"]
                }]}, "matchConditions": [{"name": "exact-approval-record",
                    "expression": f"object.metadata.name == '{RECORD}'"}],
                "validations": [{"expression": validation, "message": "The fixture approval requires its named approver"}]}})
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": name},
                "spec": {"policyName": name, "validationActions": ["Deny"], "matchResources": {
                    "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": NS}}}}})


def expiry_policy(lab):
    data = "variables.approval.data"
    exists = f"has({data})"
    fields = {
        "approver": f"'{APPROVER}'", "pod": "object.metadata.name",
        "requester": "request.userInfo.username", "profile": f"object.spec.nodeSelector['{PROFILE}']",
    }
    bound = " && ".join(f"'{key}' in {data} && {data}['{key}'] == {value}" for key, value in fields.items())
    lab.create({"apiVersion": "policies.kyverno.io/v1", "kind": "ValidatingPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail", "validationActions": ["Deny"],
                         "evaluation": {"background": {"enabled": False}},
                         "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                             "operations": ["CREATE"], "resources": ["pods"]}]},
                         "matchConditions": [{"name": "owned-sharing-exception", "expression": matches_label()}],
                         "variables": [{"name": "approval",
                                        "expression": f"resource.Get('v1', 'configmaps', '{NS}', '{RECORD}')"}],
                         "validations": [
                             {"message": MISSING, "expression": exists},
                             {"message": "SAF-0805-004 exception is outside its approved scope",
                              "expression": f"!{exists} || ({bound})"},
                             {"message": EXPIRED,
                              "expression": f"!{exists} || timestamp({data}['expiresAt']) > time.now()"},
                         ]}})


def exact_deny(result, message):
    return (result.returncode != 0 and "admission webhook" in result.stderr
            and POLICY in result.stderr and message in result.stderr)


def submit_approval(lab, actor, manifest, *, dry_run=False):
    flags = ["--dry-run=server"] if dry_run else []
    return lab.kubectl("--as", actor, "create", "-f", "-", "-o", "json", *flags,
                       payload=json.dumps(manifest), allow_failure=True)


def wait_for_missing(lab, actor, candidate, submit):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        result = submit(lab, actor, candidate)
        if exact_deny(result, MISSING):
            return result
        time.sleep(0.4)
    lab.block("The live expiry policy did not deny the exact exception request without approval")


def run(lab, pod, submit, activate_exception):
    if not RUNTIME_HELPER.is_file() or sha256(RUNTIME_HELPER.read_bytes()).hexdigest() != RUNTIME_SHA:
        lab.block("The reviewed policy consumer runtime helper is required")
    runtime = runpy.run_path(str(RUNTIME_HELPER))
    runtime["_install_kyverno"](lab)
    consumer = json.loads(lab.kubectl("-n", "kyverno", "get", "deployment",
                                      "kyverno-admission-controller", "-o", "json").stdout)
    account = consumer["spec"]["template"]["spec"]["serviceAccountName"]
    create_scope(lab, account)
    approval_policy(lab)
    expiry_policy(lab)
    candidate = pod(WORKLOAD, "shared")
    candidate["metadata"]["labels"] = {LABEL: RECORD}
    probe = pod("fixture-shared-readiness", "shared")
    probe["metadata"]["labels"] = {LABEL: RECORD}
    wait_for_missing(lab, ROUTINE, probe, submit)
    activate_exception(lab, PLACEMENT_REQUIREMENT)
    missing = wait_for_missing(lab, REQUESTER, candidate, submit)

    server_time = runtime["_server_time"]
    start_stamp, start = server_time(lab, "share-approval-start")
    expiry = start + timedelta(seconds=EXPIRY_SECONDS)
    record = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": RECORD},
              "immutable": True,
              "data": {"approver": APPROVER, "pod": WORKLOAD, "profile": "shared", "requester": REQUESTER,
                       "expiresAt": expiry.isoformat(timespec="seconds").replace("+00:00", "Z")}}
    unauthorized = submit_approval(lab, REQUESTER, record, dry_run=True)
    approved = submit_approval(lab, APPROVER, record)
    if approved.returncode:
        lab.block(f"The expected fixture approver could not record the approval: {approved.stderr.strip()}")
    stored = json.loads(approved.stdout)
    before_stamp, before = server_time(lab, "share-before")
    before_result = submit(lab, REQUESTER, candidate)
    before_end_stamp, before_end = server_time(lab, "share-before-end")
    after_stamp, after = runtime["_wait_until_server_time"](lab, expiry)
    after_result = submit(lab, REQUESTER, candidate)
    after_end_stamp, after_end = server_time(lab, "share-after-end")

    final = json.loads(lab.kubectl("get", "configmap", RECORD, "-o", "json").stdout)
    unchanged = (final.get("immutable") is True and final["data"] == stored["data"] == record["data"]
                 and all(final["metadata"][key] == stored["metadata"][key] for key in ("uid", "resourceVersion")))
    admitted = before <= before_end < expiry and before_result.returncode == 0
    expired = expiry < after <= after_end and exact_deny(after_result, EXPIRED)
    control = submit(lab, ROUTINE, pod("fixture-unexceptioned-comparator", "shared"))
    ordinary_placement_preserved = control.returncode == 0
    rejected_requester = unauthorized.returncode != 0 and "Forbidden" in unauthorized.stderr
    summary = {"missing_approval_denied": True, "requester_cannot_create_approval": rejected_requester,
               "admitted_before_expiry": admitted, "exact_expiry_denial": expired,
               "unchanged_approved_record": unchanged,
               "ordinary_placement_preserved": ordinary_placement_preserved}
    (lab.evidence / "accelerator-exception-expiry.json").write_text(json.dumps({
        **summary, "scope": "Modeled sharing profile with a live admission clock and exact immutable approval.",
        "utc_start": start_stamp, "utc_expiry": record["data"]["expiresAt"],
        "utc_allow_bracket": [before_stamp, before_end_stamp], "utc_deny_bracket": [after_stamp, after_end_stamp],
        "approval_uid_sha256": sha256(final["metadata"]["uid"].encode()).hexdigest(),
        "missing_diagnostic": missing.stderr.strip(), "expired_diagnostic": after_result.stderr.strip(),
    }, indent=2, sort_keys=True) + "\n")
    lab.check("expiry", "The same modeled sharing request is admitted only inside its attributed approval window",
              admitted and expired and unchanged and rejected_requester and ordinary_placement_preserved, summary)
