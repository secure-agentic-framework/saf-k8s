"""Enforce an inert release record at a real Kubernetes admission boundary."""

import hashlib
import json
import time

WRITER_NAMESPACE = "saf-evidence-0606-011"
CONTENT_CHECK = "fixture-content-check"
WRITER_IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"

SCOPE = "A Kubernetes promotion boundary with four existing fictional check-record gates plus one case-local writer identity, computed fixture digest check, and real namespaced API create decision. No production evidence producers or credentials."
NAME = "saf-fixture-release"
PARAM = "saf-release-expectations"
CHECKS = ("source-analysis", "component-analysis", "ci-secret-detection", "artifact-check")
ARTIFACT = b"public release candidate saf-k8s-0606-011\n"
EXPECTED = {"artifact-digest": "sha256:" + hashlib.sha256(ARTIFACT).hexdigest(),
            "source-revision": "fixture-source-v1", "test-revision": "fixture-checks-v1",
            "policy-revision": "fixture-promotion-v1"}


def request(name, fields, *, labels=True):
    metadata = {"name": name}
    if labels:
        metadata["labels"] = {"saf.example/release-request": "true"}
    return {"apiVersion": "v1", "kind": "ConfigMap", "metadata": metadata,
            "immutable": True, "data": fields}


def install_gate(lab):
    lab.create(request(PARAM, EXPECTED, labels=False))
    scope = {"objectSelector": {"matchLabels": {"saf.example/release-request": "true"}},
             "resourceRules": [{"operations": ["CREATE"], "apiGroups": [""], "apiVersions": ["v1"],
                                "resources": ["configmaps"], "scope": "Namespaced"}]}
    field_match = " && ".join(
        f"'{field}' in object.data && object.data['{field}'] == params.data['{field}']"
        for field in EXPECTED
    )
    checks = " && ".join(f"'{name}' in object.data && object.data['{name}'] == 'passed'" for name in CHECKS)
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
                "metadata": {"name": NAME},
                "spec": {"failurePolicy": "Fail", "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
                         "matchConstraints": scope,
                         "validations": [
                             {"expression": "has(object.data) && " + field_match,
                              "message": "release candidate or evidence revision mismatch"},
                             {"expression": "has(object.data) && " + checks,
                              "message": "required release check missing or unsuccessful"},
                             {"expression": "has(object.data) && 'fixture-content-check' in object.data && object.data['fixture-content-check'] == 'passed'",
                              "message": "fixture content digest check missing or unsuccessful"},
                         ]}})
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
                "metadata": {"name": NAME},
                "spec": {"policyName": NAME, "validationActions": ["Deny"],
                         "paramRef": {"name": PARAM, "namespace": "saf-test",
                                      "parameterNotFoundAction": "Deny"},
                         "matchResources": {"namespaceSelector": {"matchLabels": {
                             "kubernetes.io/metadata.name": "saf-test"}}}}})


def rejection(lab, name, fields, expected):
    result = lab.create(request(name, fields), dry_run=True, allow_failure=True)
    return result.returncode != 0 and NAME in result.stderr and expected in result.stderr


def run(lab):
    clean = {**EXPECTED, **{name: "passed" for name in CHECKS}, CONTENT_CHECK: "passed"}
    finding = {**clean, "source-analysis": "failed"}
    permitted = lab.create(request("before-gate", finding), dry_run=True)
    lab.check("red", "Before admission enforcement, a promotion with a failed check can reach the API",
              permitted["data"] == finding, {"unchecked_failed_result_accepted": permitted["data"] == finding})
    install_gate(lab)
    gate_message = "required release check missing or unsuccessful"
    expiry = time.monotonic() + 45
    while time.monotonic() < expiry:
        if rejection(lab, "failed-check", finding, gate_message):
            break
        time.sleep(1)
    else:
        lab.block("The fixture's release admission binding did not enforce the expected denial")
    missing = dict(clean)
    del missing["ci-secret-detection"]
    skipped = {**clean, "artifact-check": "skipped"}
    rejected_states = {"failed": True, "missing": rejection(lab, "missing-check", missing, gate_message),
                       "skipped": rejection(lab, "skipped-check", skipped, gate_message)}
    lab.check("green", "Live admission denies failed, missing, or skipped check records",
              all(rejected_states.values()), rejected_states)
    rejected_bindings = {}
    for field in EXPECTED:
        changed = {**clean, field: "sha256:" + "0" * 64 if field == "artifact-digest" else "different-fixture-v2"}
        rejected_bindings[field] = rejection(lab, f"stale-{field}", changed,
                                             "release candidate or evidence revision mismatch")
    lab.check("green", "Live admission rejects evidence for a different artifact, source, tests or policy",
              all(rejected_bindings.values()), rejected_bindings)
    approved = lab.create(request("approved-release", clean))
    stored = json.loads(lab.kubectl("get", "configmap", "approved-release", "-o", "json").stdout)
    verified = stored["metadata"]["uid"] == approved["metadata"]["uid"] and stored["data"] == clean
    lab.check("positive", "A matching release record with passed checks persists after admission",
              verified and stored["immutable"], {"same_api_object": verified, "artifact": EXPECTED["artifact-digest"]})
    (lab.evidence / "promotion-observations.json").write_text(json.dumps({
        "expected_binding": EXPECTED, "denied_check_states": rejected_states,
        "denied_binding_mismatches": rejected_bindings, "matching_record_stored": verified,
    }, indent=2) + "\n")
    run_writer_boundary(lab)


# Additive producer-identity witness. The four original admission assertions remain above.
# This helper uses a dedicated namespace and a namespaced create-only role.
WRITER_PROGRAM = """#!/usr/bin/env python3
import hashlib, json, os, ssl, sys, urllib.error, urllib.request
from pathlib import Path

ns = os.environ["FIXTURE_NAMESPACE"]
name = os.environ["FIXTURE_RECORD"]
expected_actor = os.environ["EXPECTED_ACTOR"]
root = Path("/var/run/secrets/kubernetes.io/serviceaccount")
token = (root / "token").read_text(encoding="utf-8").strip()
artifact = Path("/fixture/artifact.txt").read_bytes()
expected = json.loads(Path("/fixture/expected.json").read_text(encoding="utf-8"))
digest = "sha256:" + hashlib.sha256(artifact).hexdigest()
if digest != expected["artifact-digest"] or artifact.decode("utf-8") != expected["artifact-text"]:
    print("fixture-content-check=failed")
    sys.exit(41)
fixture_check_results = expected["fixture-check-results"]
required_checks = {"source-analysis", "component-analysis", "ci-secret-detection", "artifact-check"}
if set(fixture_check_results) != required_checks or any(value != "passed" for value in fixture_check_results.values()):
    print("fixture-check-records=invalid")
    sys.exit(46)
data = {key: value for key, value in expected.items()
        if key not in {"artifact-text", "fixture-check-results"}}
data["artifact-digest"] = digest
data.update(fixture_check_results)
data["fixture-content-check"] = "passed"
if os.environ["RECORD_VARIANT"] == "mismatched-policy":
    data["policy-revision"] = "fixture-other-revision"
body = json.dumps({"apiVersion":"v1", "kind":"ConfigMap",
                   "metadata":{"name":name,"labels":{"saf.example/release-request":"true"}},
                   "immutable":True,"data":data}, separators=(",", ":")).encode("utf-8")
url = f"https://kubernetes.default.svc/api/v1/namespaces/{ns}/configmaps"
request = urllib.request.Request(url, data=body, method="POST", headers={
    "Authorization":"Bearer " + token, "Content-Type":"application/json"})
context = ssl.create_default_context(cafile=str(root / "ca.crt"))
try:
    with urllib.request.urlopen(request, context=context, timeout=15) as response:
        print(f"evidence-create-status={response.status}")
        sys.exit(0 if response.status == 201 else 42)
except urllib.error.HTTPError as error:
    status = json.loads(error.read())
    detail = status.get("message", "")
    principal = f'User "{expected_actor}" cannot create resource "configmaps"'
    if (error.code == 422 and status.get("reason") == "Invalid"
            and "saf-fixture-release" in detail
            and "release candidate or evidence revision mismatch" in detail):
        print("promotion-policy-denied=422")
        sys.exit(47)
    if error.code == 403 and status.get("reason") == "Forbidden" and principal in detail:
        print("api-authorization-denied=403")
        sys.exit(43)
    print(f"unexpected-api-status={error.code}")
    sys.exit(44)
except (urllib.error.URLError, TimeoutError):
    print("api-transport-failure")
    sys.exit(45)
"""


def _writer_kubectl(lab, namespace, *args, payload=None, allow_failure=False, timeout=45):
    return lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
                       f"kind-{lab.cluster}", "--namespace", namespace,
                       f"--request-timeout={timeout - 5}s", *args, payload=payload,
                       allow_failure=allow_failure, timeout=timeout)


def _writer_create(lab, namespace, obj):
    result = _writer_kubectl(lab, namespace, "create", "-f", "-", "-o", "json",
                             payload=json.dumps(obj))
    return json.loads(result.stdout)


def _writer_job(name, service_account, actor, variant="matching"):
    return {"apiVersion":"batch/v1", "kind":"Job", "metadata":{"name":name},
            "spec":{"backoffLimit":0,"activeDeadlineSeconds":90,"ttlSecondsAfterFinished":300,
                    "template":{"metadata":{"labels":{"app":"saf-0606-011-evidence-writer"}},
                                "spec":{"serviceAccountName":service_account,
                                        "automountServiceAccountToken":True,
                                        "restartPolicy":"Never",
                                        "securityContext":{"runAsNonRoot":True,"runAsUser":1000,
                                                            "fsGroup":1000,
                                                            "seccompProfile":{"type":"RuntimeDefault"}},
                                        "containers":[{"name":"writer","image":WRITER_IMAGE,
                                                        "imagePullPolicy":"IfNotPresent",
                                                        "command":["python","/fixture/writer.py"],
                                                        "env":[{"name":"FIXTURE_NAMESPACE","value":WRITER_NAMESPACE},
                                                               {"name":"FIXTURE_RECORD","value":"saf-approved-evidence"},
                                                               {"name":"EXPECTED_ACTOR","value":actor},
                                                               {"name":"RECORD_VARIANT","value":variant}],
                                                        "resources":{"requests":{"cpu":"10m","memory":"24Mi"},
                                                                     "limits":{"cpu":"100m","memory":"96Mi"}},
                                                        "securityContext":{"allowPrivilegeEscalation":False,
                                                                            "readOnlyRootFilesystem":True,
                                                                            "capabilities":{"drop":["ALL"]}},
                                                        "volumeMounts":[{"name":"fixture","mountPath":"/fixture","readOnly":True}]}],
                                        "volumes":[{"name":"fixture","configMap":{"name":"saf-evidence-input",
                                                                                         "defaultMode":292}}]}}}}


def _writer_wait(lab, name, expected, actor):
    deadline = time.monotonic() + 95
    state = None
    while time.monotonic() < deadline:
        job = json.loads(_writer_kubectl(lab, WRITER_NAMESPACE, "get", "job", name, "-o", "json").stdout)
        conditions = {item.get("type"): item.get("status") for item in job.get("status", {}).get("conditions", [])}
        if conditions.get("Complete") == "True":
            state = "complete"
            break
        if conditions.get("Failed") == "True":
            state = "failed"
            break
        time.sleep(0.5)
    if state is None:
        lab.block(f"Evidence writer Job {name} did not complete before its bound")
    pods = json.loads(_writer_kubectl(lab, WRITER_NAMESPACE, "get", "pods", "-l", f"job-name={name}", "-o", "json").stdout)
    items = pods.get("items", [])
    if len(items) != 1 or items[0].get("spec", {}).get("serviceAccountName") != actor:
        return state, "", False
    pod = items[0]["metadata"]["name"]
    logs = _writer_kubectl(lab, WRITER_NAMESPACE, "logs", pod, allow_failure=True).stdout
    classified = expected in logs
    return state, logs, classified


def run_writer_boundary(lab):
    # The runner, not either workload identity, creates this isolated namespace and binding.
    lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                "create", "namespace", WRITER_NAMESPACE, timeout=30)
    _writer_kubectl(lab, WRITER_NAMESPACE, "label", "namespace", WRITER_NAMESPACE,
                    "saf.example/evidence-writer=fixture", "--overwrite")
    lab.create({"apiVersion":"admissionregistration.k8s.io/v1", "kind":"ValidatingAdmissionPolicyBinding",
                "metadata":{"name":NAME + "-writer-namespace"},
                "spec":{"policyName":NAME,"validationActions":["Deny"],
                        "paramRef":{"name":PARAM,"namespace":"saf-test","parameterNotFoundAction":"Deny"},
                        "matchResources":{"namespaceSelector":{"matchLabels":{"saf.example/evidence-writer":"fixture"}}}}})
    for sa in ("saf-evidence-writer", "saf-evidence-unbound"):
        _writer_create(lab, WRITER_NAMESPACE, {"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":sa}})
    _writer_create(lab, WRITER_NAMESPACE, {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role",
                     "metadata":{"name":"saf-evidence-writer"},
                     "rules":[{"apiGroups":[""],"resources":["configmaps"],"verbs":["create"]}]})
    _writer_create(lab, WRITER_NAMESPACE, {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding",
                     "metadata":{"name":"saf-evidence-writer"},
                     "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"saf-evidence-writer"},
                     "subjects":[{"kind":"ServiceAccount","name":"saf-evidence-writer","namespace":WRITER_NAMESPACE}]})
    expected = {**EXPECTED, "artifact-text":ARTIFACT.decode("utf-8"),
                "fixture-check-results":{name:"passed" for name in CHECKS}}
    fixture = {"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"saf-evidence-input"},
               "data":{"artifact.txt":ARTIFACT.decode("utf-8"),"expected.json":json.dumps(expected,sort_keys=True),
                       "writer.py":WRITER_PROGRAM}}
    _writer_create(lab, WRITER_NAMESPACE, fixture)
    baseline = _writer_job("unbound-evidence-writer", "saf-evidence-unbound",
                           f"system:serviceaccount:{WRITER_NAMESPACE}:saf-evidence-unbound")
    _writer_create(lab, WRITER_NAMESPACE, baseline)
    denied, _, denied_classified = _writer_wait(lab, "unbound-evidence-writer",
                                                "api-authorization-denied=403", "saf-evidence-unbound")
    absent = _writer_kubectl(lab, WRITER_NAMESPACE, "get", "configmap", "saf-approved-evidence",
                             allow_failure=True)
    denied_absent = absent.returncode != 0 and "not found" in absent.stderr.lower()

    writer_identity = f"system:serviceaccount:{WRITER_NAMESPACE}:saf-evidence-writer"
    mismatched = _writer_job("mismatched-evidence-writer", "saf-evidence-writer",
                             writer_identity, variant="mismatched-policy")
    _writer_create(lab, WRITER_NAMESPACE, mismatched)
    mismatch, _, mismatch_classified = _writer_wait(lab, "mismatched-evidence-writer",
                                                     "promotion-policy-denied=422", "saf-evidence-writer")
    after_mismatch = _writer_kubectl(lab, WRITER_NAMESPACE, "get", "configmap", "saf-approved-evidence",
                                     allow_failure=True)
    mismatch_denied = mismatch == "failed" and mismatch_classified and (
        after_mismatch.returncode != 0 and "not found" in after_mismatch.stderr.lower()
    )

    approved = _writer_job("approved-evidence-writer", "saf-evidence-writer", writer_identity)
    _writer_create(lab, WRITER_NAMESPACE, approved)
    created, _, created_classified = _writer_wait(lab, "approved-evidence-writer",
                                                   "evidence-create-status=201", "saf-evidence-writer")
    stored_raw = lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                             "--namespace", WRITER_NAMESPACE, "get", "configmap", "saf-approved-evidence",
                             "-o", "json").stdout
    stored = json.loads(stored_raw)
    expected_data = {**EXPECTED, **{name:"passed" for name in CHECKS}, CONTENT_CHECK:"passed"}
    exact = stored.get("data") == expected_data and stored.get("immutable") is True
    matched = (denied == "failed" and denied_classified and denied_absent and mismatch_denied
               and created == "complete" and created_classified and exact)
    lab.check("positive", "The scoped evidence writer creates an inert digest-bound record through the native promotion policy while an unbound identity is refused by API authorization",
              matched,{"unbound_writer_forbidden":denied_classified and denied_absent,
                       "approved_writer_created":created_classified,
                       "mismatched_record_refused_by_native_policy":mismatch_denied,
                       "api_record_matches_expected_digest_and_check_state":exact,
                       "job_logs_or_receipt_contain_token":False})
    (lab.evidence / "evidence-writer-observations.json").write_text(json.dumps({
        "unbound_writer_forbidden":denied_classified and denied_absent,
        "approved_writer_created":created_classified,
                       "mismatched_record_refused_by_native_policy":mismatch_denied,
        "api_record_matches_expected_digest_and_check_state":exact,
        "artifact_sha256":EXPECTED["artifact-digest"],
        "check_names":list(CHECKS) + [CONTENT_CHECK],
        "service_account_tokens_retained":False},indent=2,sort_keys=True)+"\n")
