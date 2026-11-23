"""Require a reviewable, scoped emergency runbook in the actual Kubernetes API."""
import importlib.util
import json
from pathlib import Path
import time

NS = "saf-test"
NAME = "fixture-emergency-runbook"
NORMAL = "fixture-normal-provider"
FALLBACK = "fixture-independent-recovery"
REVIEWER = "fixture-recovery-reviewer"
ALTERNATE = "fixture-unrelated-runbook"
ADMISSION = "admissionregistration.k8s.io/v1"
RBAC = "rbac.authorization.k8s.io/v1"
DENIAL = "a complete scoped emergency runbook is required"
RUNBOOK = {
    "owner": "fixture-authorized-owner",
    "normalDependency": NORMAL,
    "activationTrigger": "normal issuer cannot create a new session",
    "fallbackAuthority": FALLBACK,
    "approvedOperation": "read the named recovery record in saf-test",
    "approvalReference": "fixture-approval-01",
    "evidence": "record observed identity and request outcome",
    "disengagement": "withdraw temporary authorization and restore normal access",
    "exerciseCadence": "organization-defined annual fixture exercise",
}
SCOPE = (
    "A real admission policy enforces owner, scope, activation, independent fallback "
    "and disengagement fields for a defined Kubernetes runbook record. An authorized "
    "reviewer reads the accepted document; unrelated records remain independent. "
    "This verifies the documented workflow boundary, while SAF-K8S-0405-020 tests a "
    "separate live activation and execution scenario."
)


def recovery_fixture():
    path = Path(__file__).resolve().parents[1] / "SAF-K8S-0405-020" / "case.py"
    spec = importlib.util.spec_from_file_location("saf_fixture_recovery", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def submit(lab, data, name=NAME, dry=False):
    payload = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "data": data}
    flag = ("--dry-run=server",) if dry else ()
    return lab.kubectl("create", "-f", "-", "-o", "json", *flag,
                       payload=json.dumps(payload), allow_failure=True)


def require(lab, fixture):
    fields = ",".join(repr(field) for field in RUNBOOK)
    expression = (
        f"has(object.data) && [{fields}].all(field, field in object.data && object.data[field] != '') "
        f"&& object.data.normalDependency == '{NORMAL}' && object.data.fallbackAuthority == '{FALLBACK}' "
        "&& object.data.normalDependency != object.data.fallbackAuthority "
        f"&& object.data.approvedOperation == '{RUNBOOK['approvedOperation']}'"
    )
    fixture.put(lab, "ValidatingAdmissionPolicy", NAME, ADMISSION, spec={
        "failurePolicy": "Fail",
        "matchConstraints": {"resourceRules": [
            {"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"],
             "resources": ["configmaps"]},
        ]},
        "matchConditions": [{"name": "named-runbook",
                             "expression": f"request.namespace == '{NS}' && object.metadata.name == '{NAME}'"}],
        "validations": [{"expression": expression, "message": DENIAL}],
    })
    fixture.put(lab, "ValidatingAdmissionPolicyBinding", NAME, ADMISSION,
                 spec={"policyName": NAME, "validationActions": ["Deny"]})


def run(lab):
    fixture = recovery_fixture()
    incomplete = {"owner": RUNBOOK["owner"], "normalDependency": NORMAL}
    initial = submit(lab, incomplete)
    red = {"incomplete_record_persists_without_gate": initial.returncode == 0,
           "record_has_no_fallback_or_disengagement": initial.returncode == 0
           and set(json.loads(initial.stdout)["data"]) == set(incomplete)}
    lab.check("red", "Kubernetes alone can store a document without the required recovery procedure",
              all(red.values()), red)
    lab.kubectl("delete", "configmap", NAME, "--wait=true")
    require(lab, fixture)
    for _ in range(15):
        missing = submit(lab, incomplete, dry=True)
        if DENIAL in missing.stderr:
            break
        time.sleep(.5)
    same = submit(lab, dict(RUNBOOK, fallbackAuthority=NORMAL), dry=True)
    outside = submit(lab, dict(RUNBOOK, approvedOperation="update unrelated fixture records"), dry=True)
    without_exit = submit(lab, dict(RUNBOOK, disengagement=""), dry=True)
    enforced = {"incomplete_runbook_denied": DENIAL in missing.stderr,
                "shared_failure_dependency_denied": DENIAL in same.stderr,
                "out_of_scope_operation_denied": DENIAL in outside.stderr,
                "missing_disengagement_denied": DENIAL in without_exit.stderr}
    lab.check("green", "The native gate rejects missing or mismatched recovery procedure details",
              all(enforced.values()), enforced)

    accepted = submit(lab, RUNBOOK)
    neighbor = submit(lab, {"marker": "independent"}, name=ALTERNATE)
    fixture.put(lab, "ServiceAccount", REVIEWER, automountServiceAccountToken=False)
    fixture.put(lab, "Role", NAME, RBAC, rules=[{
        "apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"], "resourceNames": [NAME],
    }])
    fixture.put(lab, "RoleBinding", NAME, RBAC,
                roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": NAME},
                subjects=[{"kind": "ServiceAccount", "name": REVIEWER, "namespace": NS}])
    profile = fixture.identity(lab, REVIEWER, "runbook-review")
    retained = lab.command("kubectl", "--kubeconfig", str(profile), "--context", "fixture",
                           "--request-timeout=6s", "get",
                           f"--raw=/api/v1/namespaces/{NS}/configmaps/{NAME}", timeout=12)
    positive = {"complete_reviewable_runbook_persisted": accepted.returncode == 0
                and json.loads(retained.stdout)["data"] == RUNBOOK,
                "unrelated_resource_unchanged_by_policy": neighbor.returncode == 0}
    lab.check("positive", "An authorized reviewer can retrieve the complete procedure",
              all(positive.values()), positive)
    (lab.evidence / "emergency-procedure-observations.json").write_text(json.dumps({
        "baseline": red, "enforced": enforced, "positive": positive,
    }, indent=2) + "\n")
