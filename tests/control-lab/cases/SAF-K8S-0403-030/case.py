"""Verify the governed admission behavior of a current and overdue exception."""
from datetime import datetime, timedelta, timezone
import json
import time

from fixtures import container, pod

NS = "saf-test"
REGISTRY = "fixture-env-exception"
POLICY = "fixture-environment-exception-policy"
WORKLOAD = "fixture-approved-workload"
SECRET = "fixture-public-marker"
ACTOR = f"system:serviceaccount:{NS}:deployer"
MARKER = "PUBLIC_SYNTHETIC_ENV_EXCEPTION_0403_030"
DENIED = "Secret-backed environment delivery requires the current scoped fixture approval"
SCOPE = (
    "A named ConfigMap approval limits a test-only deployment origin and Pod identity. "
    "Native Kubernetes admission verifies an explicit compensating container setting and "
    "effective review state. A reconciliation step marks an overdue entry expired. Actual "
    "production exception inventory, policy scope, reviewer authenticity and ongoing "
    "compensating control verification need separate evidence."
)
API = "admissionregistration.k8s.io/v1"
RBAC = "rbac.authorization.k8s.io/v1"
USES_SECRET = (
    "(has(c.env) && c.env.exists(e, has(e.valueFrom) && has(e.valueFrom.secretKeyRef))) "
    "|| (has(c.envFrom) && c.envFrom.exists(e, has(e.secretRef)))"
)


def put(lab, kind, name, version="v1", **fields):
    return lab.create({"apiVersion": version, "kind": kind, "metadata": {"name": name}, **fields})


def fixtures(lab):
    put(lab, "Secret", SECRET, stringData={"public-marker": MARKER})
    for name in ("deployer", "fixture-exception-workload"):
        put(lab, "ServiceAccount", name, automountServiceAccountToken=False)
    put(lab, "Role", "fixture-deploy-only", RBAC, rules=[
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]},
        {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [REGISTRY], "verbs": ["get"]},
    ])
    put(lab, "RoleBinding", "fixture-deploy-only", RBAC,
        subjects=[{"kind": "ServiceAccount", "name": "deployer", "namespace": NS}],
        roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "fixture-deploy-only"})
    lab.kubectl("label", "namespace", NS, "saf-k8s.example/fixture-exception=governed")


def entry(now):
    return {"record": "fixture-review-0403-030", "owner": "fixture-application-owner",
            "approval": "fixture-security-review", "rationale": "case-owned dependency",
            "compensatingControl": "read-only-root", "workload": WORKLOAD,
            "serviceAccount": "fixture-exception-workload", "deployer": ACTOR,
            "reviewDue": (now + timedelta(days=1)).isoformat(), "state": "pending"}


def replace_entry(lab, **updated):
    return lab.kubectl("patch", "configmap", REGISTRY, "--type=merge", "-p",
                       json.dumps({"data": updated}), "-o", "name")


def reconcile(lab, now):
    out = lab.kubectl("get", "configmap", REGISTRY, "-o", "json").stdout
    data = json.loads(out)["data"]
    required = ("record", "owner", "approval", "rationale", "compensatingControl", "reviewDue")
    if any(not data.get(field) for field in required):
        status = "incomplete"
    elif datetime.fromisoformat(data["reviewDue"]) <= now:
        status = "overdue"
    else:
        status = "current"
    replace_entry(lab, state=status, lastEvaluated=now.isoformat())
    return status


def install(lab):
    governed = (
        "object.spec.containers.exists(c, " + USES_SECRET + ") || "
        "(has(object.spec.initContainers) && object.spec.initContainers.exists(c, " + USES_SECRET + "))"
    )
    allowed = (
        "params != null && has(params.data) && "
        "['record','owner','approval','rationale','compensatingControl','reviewDue','lastEvaluated',"
        "'state','workload','serviceAccount','deployer'].all(k, k in params.data && size(params.data[k]) > 0) && "
        "params.data.state == 'current' && params.data.workload == object.metadata.name && "
        "params.data.serviceAccount == object.spec.serviceAccountName && "
        "params.data.deployer == request.userInfo.username && params.data.compensatingControl == 'read-only-root' && "
        "object.spec.containers.all(c, has(c.securityContext) && has(c.securityContext.readOnlyRootFilesystem) "
        "&& c.securityContext.readOnlyRootFilesystem) && !has(object.spec.initContainers)"
    )
    put(lab, "ValidatingAdmissionPolicy", POLICY, API, spec={
        "failurePolicy": "Fail", "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
        "matchConstraints": {"resourceRules": [
            {"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"]}]},
        "validations": [{"expression": f"!({governed}) || ({allowed})", "message": DENIED}],
    })
    put(lab, "ValidatingAdmissionPolicyBinding", POLICY, API, spec={
        "policyName": POLICY, "validationActions": ["Deny"],
        "paramRef": {"name": REGISTRY, "namespace": NS, "parameterNotFoundAction": "Deny"},
        "matchResources": {"namespaceSelector": {"matchLabels": {"saf-k8s.example/fixture-exception": "governed"}}},
    })


def deploy(lab, name=WORKLOAD, *, secret=True, protected=True, probe=True):
    options = {}
    if secret:
        options["env"] = [{"name": "FIXTURE_VALUE", "valueFrom": {
            "secretKeyRef": {"name": SECRET, "key": "public-marker"}}}]
    unit = container("test", command=["sh", "-c", 'test "$FIXTURE_VALUE" = "$1" && printf "%s\\n" approved-fixture-read',
                                      "fixture", MARKER], **options)
    unit["securityContext"]["readOnlyRootFilesystem"] = protected
    request = pod(name, [unit], serviceAccountName="fixture-exception-workload", automountServiceAccountToken=False)
    flags = ["--dry-run=server"] if probe else []
    return lab.kubectl("--as=" + ACTOR, "create", "-f", "-", "-o", "name", *flags,
                       payload=json.dumps(request), allow_failure=True)


def was_denied(result):
    return result.returncode != 0 and DENIED in result.stderr


def await_decision(lab, expected):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        decision = deploy(lab)
        if (expected == "allow" and decision.returncode == 0) or (expected == "deny" and was_denied(decision)):
            return True
        time.sleep(.4)
    return False


def run(lab):
    fixtures(lab)
    ungoverned = deploy(lab).returncode == 0
    now = datetime.now(timezone.utc)
    put(lab, "ConfigMap", REGISTRY, data=entry(now))
    install(lab)
    pending_denied = await_decision(lab, "deny")
    initial = {"no_policy_accepts_secret_env": ungoverned, "pending_approval_denied": pending_denied}
    lab.check("red", "The ungoverned workload would pass and a pending record cannot authorize it",
              all(initial.values()), initial)

    current = reconcile(lab, now) == "current"
    if not await_decision(lab, "allow"):
        lab.block("The reconciled approval was not available to admission")
    result = deploy(lab, probe=False)
    if result.returncode:
        lab.block("The governed approved workload was not created")
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{WORKLOAD}",
                "--timeout=95s", timeout=105)
    executed = lab.kubectl("logs", WORKLOAD).stdout.strip() == "approved-fixture-read"
    denied_wrong = was_denied(deploy(lab, "fixture-unlisted-workload"))
    unauthorized = lab.kubectl("--as=" + ACTOR, "patch", "configmap", REGISTRY, "--type=merge",
                               "-p", '{"data":{"state":"current"}}', allow_failure=True)
    lab.kubectl("delete", "pod", WORKLOAD, "--wait=true")
    denied_without_compensation = was_denied(deploy(lab, protected=False))
    allowed = {"current_review_approved_and_workload_executed": current and executed,
               "unlisted_workload_denied": denied_wrong,
               "missing_compensation_denied": denied_without_compensation,
               "deployer_cannot_approve": unauthorized.returncode != 0 and "(Forbidden)" in unauthorized.stderr}
    lab.check("green", "An approved workload executes under its recorded compensation and unapproved paths are denied",
              all(allowed.values()), allowed)

    next_review = now + timedelta(days=2)
    overdue = reconcile(lab, next_review) == "overdue"
    final = {"overdue_entry_cannot_authorize": overdue and await_decision(lab, "deny"),
             "nonsecret_workload_admitted": deploy(lab, "fixture-ordinary", secret=False).returncode == 0}
    lab.check("positive", "Re-review expiry removes the exception while ordinary deployment still passes",
              all(final.values()), final)
    (lab.evidence / "environment-exception-observations.json").write_text(json.dumps({
        "baseline": initial, "current_review": allowed, "later_review": final,
        "review_clock": "controlled fixture advances one recorded review cycle",
    }, indent=2) + "\n")
