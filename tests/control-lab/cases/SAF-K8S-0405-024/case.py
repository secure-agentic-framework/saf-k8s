"""Observe deadline-driven authorization withdrawal and credential retirement."""
import importlib.util
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
RBAC = "rbac.authorization.k8s.io/v1"
NS = "saf-test"
READER = "fixture-expiring-reader"
SEPARATE = "fixture-independent-reader"
SCHEDULE = "fixture-retirement-schedule"
CONTROLLER = "fixture-grant-retirement"
IMAGE = ("docker.io/library/python:3.13.2-alpine@sha256:"
         "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352")
SCOPE = (
    "A real Kubernetes Job with named-object authority withdraws a fixture RoleBinding "
    "only after its recorded approval window. The original credential continues authenticating "
    "but loses the effective read. An independent approved reader retains access. This "
    "also verifies native invalidation of a token bound to an empty Secret that the "
    "same controller retires at the deadline. External issuers and certificates have "
    "distinct mechanisms."
)


def recovery_fixture():
    path = HERE.parent / "SAF-K8S-0405-020" / "case.py"
    spec = importlib.util.spec_from_file_location("saf_fixture_recovery", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def schedule(lab, value):
    lab.kubectl("patch", "configmap", SCHEDULE, "--type=merge",
                "-p", json.dumps({"data": {"deadline": str(value)}}), "-o", "name")


def start(lab, fixture):
    group = "rbac.authorization.k8s.io"
    fixture.put(lab, "ServiceAccount", CONTROLLER, automountServiceAccountToken=False)
    fixture.put(lab, "Role", CONTROLLER, RBAC, rules=[
        {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"], "resourceNames": [SCHEDULE]},
        {"apiGroups": [group], "resources": ["rolebindings"], "verbs": ["delete"], "resourceNames": [READER]},
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["delete"],
         "resourceNames": [fixture.REFERENCE]},
    ])
    fixture.put(lab, "RoleBinding", CONTROLLER, RBAC,
                roleRef={"apiGroup": group, "kind": "Role", "name": CONTROLLER},
                subjects=[{"kind": "ServiceAccount", "name": CONTROLLER, "namespace": NS}])
    fixture.put(lab, "ConfigMap", CONTROLLER, data={"reaper.py": (HERE/"reaper.py").read_text()})
    fixture.put(lab, "Job", CONTROLLER, "batch/v1", spec={
        "backoffLimit": 0, "activeDeadlineSeconds": 150,
        "template": {"spec": {
            "restartPolicy": "Never", "serviceAccountName": CONTROLLER, "automountServiceAccountToken": True,
            "containers": [{"name": "controller", "image": IMAGE, "command": ["python", "/scripts/reaper.py"],
                            "volumeMounts": [{"name": "program", "mountPath": "/scripts", "readOnly": True}],
                            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                "allowPrivilegeEscalation": False,
                                                "capabilities": {"drop": ["ALL"]},
                                                "seccompProfile": {"type": "RuntimeDefault"}}}],
            "volumes": [{"name": "program", "configMap": {"name": CONTROLLER}}],
        }},
    })
    for _ in range(12):
        found = lab.kubectl("get", "pod", "-l", "job-name="+CONTROLLER, "-o", "name").stdout.strip()
        if found:
            lab.kubectl("wait", "--for=condition=Ready", found, "--timeout=95s", timeout=105)
            return
        time.sleep(.5)
    lab.block("The fixture retirement Job did not get a Pod")


def run(lab):
    fixture = recovery_fixture()
    fixture.put(lab, "ConfigMap", fixture.READ, data={"marker": fixture.MARKER})
    fixture.put(lab, "ConfigMap", SCHEDULE, data={"deadline": str(int(time.time()) - 5)})
    fixture.put(lab, "Role", fixture.READ, RBAC, rules=[{
        "apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"], "resourceNames": [fixture.READ],
    }])
    for account in (READER, SEPARATE):
        fixture.put(lab, "ServiceAccount", account, automountServiceAccountToken=False)
        fixture.approved(lab, account)
    fixture.put(lab, "Secret", fixture.REFERENCE)
    expiring = fixture.identity(lab, READER, "expiration")
    bound = fixture.identity(lab, READER, "bound-expiration", reference=True)
    separate = fixture.identity(lab, SEPARATE, "expiration-neighbor")
    baseline = {"elapsed_record_alone_leaves_effective_access": fixture.await_read(lab, expiring, "allowed") == "allowed",
                "independent_approved_principal_also_has_access": fixture.read(lab, separate) == "allowed"}
    lab.check("red", "A deadline record alone does not remove effective authorization",
              all(baseline.values()), baseline)

    if fixture.await_read(lab, bound, "allowed") != "allowed":
        lab.block("Bound fixture identity did not have the approved read before activation")

    schedule(lab, "pending")
    start(lab, fixture)
    deadline = int(time.time()) + 12
    schedule(lab, deadline)
    before = fixture.read(lab, expiring) == "allowed" and time.time() < deadline
    bound_before = fixture.read(lab, bound) == "allowed" and time.time() < deadline
    lab.kubectl("wait", "--for=condition=Complete", "job/"+CONTROLLER, "--timeout=45s", timeout=53)
    report = json.loads(lab.kubectl("logs", "job/"+CONTROLLER, "--all-containers=false").stdout)
    enforced = {"reader_available_before_approved_deadline": before,
                "controller_reaches_deadline_before_withdrawal": report["approved_deadline_reached"],
                "scoped_binding_removed_automatically": report["scoped_binding_deleted"],
                "same_authenticated_caller_loses_read": fixture.await_read(lab, expiring, "forbidden") == "forbidden"}
    lab.check("green", "The scoped controller automatically withdraws the temporary grant",
              all(enforced.values()), enforced)
    positive = {"separate_grant_still_effective": fixture.read(lab, separate) == "allowed",
                "ended_grant_remains_unavailable": fixture.read(lab, expiring) == "forbidden"}
    lab.check("positive", "Retiring the temporary grant preserves independent approved access",
              all(positive.values()), positive)
    issuer = {
        "bound_reader_available_before_deadline": bound_before,
        "named_credential_anchor_deleted": report["credential_anchor_deleted"],
        "same_bound_credential_rejected_by_api_authenticator": (
            fixture.await_read(lab, bound, "unauthenticated") == "unauthenticated"
        ),
        "independent_credential_stays_authorized": fixture.read(lab, separate) == "allowed",
    }
    lab.check("identity", "The same deadline also retires the scoped native bound credential",
              all(issuer.values()), issuer)
    (lab.evidence / "emergency-retirement-observations.json").write_text(json.dumps({
        "baseline": baseline, "enforced": enforced, "preserved": positive, "issuer": issuer,
    }, indent=2) + "\n")
