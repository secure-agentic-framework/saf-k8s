"""Draft admission-policy probe for policy exception record governance."""
import copy
import json
import os
import runpy
import subprocess
import time
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
FIXED_CUTOFF = "2026-11-22T00:00:00Z"
APPROVER = "fixture-exception-approver"
OBSERVER = "fixture-exception-observer"
CLOCK = "fixture-exception-clock"
POLICY = "saf-lab-1006-010-exception-governance"
SCOPE = ("Kubernetes v1.36.1. A namespaced exception record is tested before and after governance, "
         "using an authenticated scoped fixture approver and an observer without record write permission. "
         "The case checks exact scope, attributable approval, metadata, and a protected admission cutoff. Kyverno independently consumes the same scoped record before and after its automatic expiry.")


def _client(lab, config, namespace, *args, payload=None):
    return lab.command("kubectl", "--kubeconfig", str(config), "--context", "fixture",
                       "--namespace", namespace, "--request-timeout=15s", *args,
                       payload=json.dumps(payload) if payload is not None else None,
                       timeout=25, allow_failure=True)


def _fixture_config(lab, account):
    admin = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}"]
    result = subprocess.run(
        [*admin, "--namespace", NAMESPACE, "create", "token", account, "--duration=10m"],
        text=True, capture_output=True, env=lab.env, timeout=25,
    )
    if result.returncode:
        lab.block("Could not mint a short-lived token for the case-owned ServiceAccount")
    token = result.stdout.strip()
    if not token or any(ch.isspace() for ch in token):
        lab.block("kubectl create token returned an invalid token value")
    view = subprocess.run([*admin, "config", "view", "--minify", "--flatten", "--raw", "-o", "json"],
                          text=True, capture_output=True, env=lab.env, timeout=25)
    if view.returncode:
        lab.block("Could not read the case-owned API endpoint and its CA")
    source = json.loads(view.stdout)["clusters"][0]["cluster"]
    cluster = {"server": source["server"], "certificate-authority-data": source["certificate-authority-data"]}
    credential = {"apiVersion": "v1", "kind": "Config", "current-context": "fixture",
                  "clusters": [{"name": "fixture", "cluster": cluster}],
                  "contexts": [{"name": "fixture", "context": {"cluster": "fixture", "user": "fixture"}}],
                  "users": [{"name": "fixture", "user": {"token": token}}]}
    path = lab.kubeconfig.with_name(account + "-credential")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump(credential, output)
    return path


def load_fixtures():
    return json.loads((CASE_DIR / "fixtures.json").read_text())


def with_identity(obj, username):
    result = copy.deepcopy(obj)
    approval = result.get("spec", {}).get("approval")
    if isinstance(approval, dict) and "approverIdentity" in approval:
        approval["approverIdentity"] = username
    return result


def identity(name):
    return f"system:serviceaccount:{NAMESPACE}:{name}"


def submit(lab, config, obj):
    return _client(lab, config, NAMESPACE, "create", "-f", "-", "-o", "json", "--dry-run=server", payload=obj)


def created_as_expected(result, obj):
    if result.returncode:
        return False
    try:
        created = json.loads(result.stdout)
    except json.JSONDecodeError:
        return False
    metadata = created.get("metadata", {})
    return created.get("kind") == obj.get("kind") and metadata.get("name") == obj.get("metadata", {}).get("name")


def denied_by_policy(result, detail):
    return (result.returncode != 0 and "ValidatingAdmissionPolicy" in result.stderr
            and POLICY in result.stderr and detail in result.stderr)


def wait_denial(probe, detail):
    deadline = time.monotonic() + 25
    while True:
        result = probe()
        if denied_by_policy(result, detail) or time.monotonic() >= deadline:
            return result
        time.sleep(0.5)


def run(lab):
    fixtures = load_fixtures()
    lab.apply(CASE_DIR / "exception-record-crd.yaml")
    lab.kubectl("wait", "--for=condition=Established", "crd/policyexceptions.saf-lab.example", "--timeout=30s")
    lab.apply(CASE_DIR / "inert-workload.yaml")
    for actor in (APPROVER, OBSERVER):
        lab.kubectl("create", "serviceaccount", actor)
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": "fixture-record-approver"}, "rules": [
                    {"apiGroups": ["saf-lab.example"], "resources": ["policyexceptions"], "verbs": ["create"]},
                    {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"], "resourceNames": [CLOCK]},
                ]})
    lab.kubectl("create", "rolebinding", "fixture-record-approver", "--role=fixture-record-approver",
                f"--serviceaccount={NAMESPACE}:{APPROVER}")
    lab.kubectl("create", "configmap", CLOCK, f"--from-literal=cutoff={FIXED_CUTOFF}")
    approver, observer = (_fixture_config(lab, actor) for actor in (APPROVER, OBSERVER))
    authenticated = {}
    for actor, credential in ((APPROVER, approver), (OBSERVER, observer)):
        result = _client(lab, credential, NAMESPACE, "auth", "whoami", "-o", "json")
        authenticated[actor] = (not result.returncode
                                and json.loads(result.stdout)["status"]["userInfo"]["username"] == identity(actor))
    lab.check("positive", "The API independently authenticates both fixture identities",
              all(authenticated.values()), authenticated)
    cases = {key: with_identity(value, identity(APPROVER)) for key, value in fixtures.items()}
    before = {key: created_as_expected(submit(lab, approver, cases[key]), cases[key])
              for key in ("broad_scope", "stale_exact")}
    lab.check("red", "Without admission governance the approved writer can submit broad and stale records",
              all(before.values()), before)

    lab.kubectl("label", "namespace", NAMESPACE, "saf-lab.example/exception-test=true")
    lab.apply(CASE_DIR / "policy.yaml")
    scope = "exception scope must match the named policy and workload"
    expiry = "exception expiry must follow the protected cutoff"
    approval = "exception requires approval attributed to the authenticated caller and justification"
    broad = wait_denial(lambda: submit(lab, approver, cases["broad_scope"]), scope)
    lab.check("green", "The identical broad-scope record is refused by its named rule",
              denied_by_policy(broad, scope), {"scope_rule_matched": denied_by_policy(broad, scope)})
    exact = cases["exact_approved"]
    admitted = created_as_expected(submit(lab, approver, exact), exact)
    lab.check("positive", "The approved writer can submit the exact attributed and justified record",
              admitted, {"approved_record_admitted": admitted})
    for key, obj, rule in (("stale_exact", cases["stale_exact"], expiry),
                           ("missing_approver", cases["missing_approver"], approval),
                           ("missing_justification", cases["missing_justification"], approval),
                           ("missing_expiration", cases["missing_expiration"], expiry),
                           ("different_approver", with_identity(exact, identity(OBSERVER)), approval)):
        matches = denied_by_policy(submit(lab, approver, obj), rule)
        lab.check("green", f"Admission reports the expected exception rule for {key}",
                  matches, {"policy_rule_matched": matches, "expected": rule})
    unauthorized = submit(lab, observer, with_identity(exact, identity(OBSERVER)))
    forbidden = bool(unauthorized.returncode and "(Forbidden)" in unauthorized.stderr
                     and identity(OBSERVER) in unauthorized.stderr
                     and 'cannot create resource "policyexceptions"' in unauthorized.stderr)
    lab.check("green", "RBAC rejects record creation from the authenticated fixture observer",
              forbidden, {"observer_write_forbidden": forbidden})
    patch = json.dumps({"data": {"cutoff": "2026-12-22T00:00:01Z"}})
    write = _client(lab, approver, NAMESPACE, "patch", "configmap", CLOCK, "--type=merge", "-p", patch)
    protected = bool(write.returncode and "(Forbidden)" in write.stderr and identity(APPROVER) in write.stderr
                     and 'cannot patch resource "configmaps"' in write.stderr)
    lab.check("positive", "The approved record writer cannot change the protected cutoff",
              protected, {"cutoff_write_forbidden": protected})
    lab.kubectl("patch", "configmap", CLOCK, "--type=merge", "-p", patch)
    expired = wait_denial(lambda: submit(lab, approver, exact), expiry)
    lab.check("green", "The same previously approved record is refused after the protected cutoff advances",
              denied_by_policy(expired, expiry), {"expiry_rule_matched": denied_by_policy(expired, expiry)})

    runtime = runpy.run_path(str(CASE_DIR / "runtime_expiry.py"))
    runtime["run"](lab, approver, exact)
