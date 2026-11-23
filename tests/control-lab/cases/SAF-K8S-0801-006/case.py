"""Run a live admission check against an operator-owned, synthetic evidence record."""

import json
import time

NAMESPACE = "saf-test"
PARAMETER = "fixture-platform-record"
POLICY = "fixture-platform-approval"
REASON = "Fixture platform evidence does not authorize this workload"
WORKLOAD = "guarded-approved"
SUBMITTER = "fixture-workload-submitter"
ANNOTATION = "fixture.example/"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
SCOPE = ('Live reassignment admission based on an inert transition record; no physical device, '
 'memory or reset involved.')
MATCHED = ('allocation', 'transition', 'target-trust')
RECORD_RULES = ["params.data['evidence-kind'] == 'reviewed-device-attestation'",
 "params.data['evidence-id'] != ''"]
APPROVED_FIELDS = {'allocation': 'fixture-allocation-25',
 'transition': 'fixture-transition-generation-8',
 'target-trust': 'fixture-trust-b'}
APPROVED_RECORD = {'allocation': 'fixture-allocation-25',
 'transition': 'fixture-transition-generation-8',
 'target-trust': 'fixture-trust-b',
 'evidence-kind': 'reviewed-device-attestation',
 'evidence-id': 'synthetic-attestation-8',
 'state': 'approved',
 'workload': 'guarded-approved'}
INITIAL_RECORD = {'allocation': 'fixture-allocation-25',
 'transition': 'fixture-transition-generation-8',
 'target-trust': 'fixture-trust-b',
 'evidence-kind': 'reset-reported',
 'evidence-id': '',
 'state': 'quarantined',
 'workload': 'guarded-approved'}
CLOSED_RECORD = {'allocation': 'fixture-allocation-25',
 'transition': 'fixture-transition-generation-8',
 'target-trust': 'fixture-trust-b',
 'evidence-kind': 'reviewed-device-attestation',
 'evidence-id': 'synthetic-attestation-8',
 'state': 'new-transition',
 'workload': 'guarded-approved'}
PRE_CLAIM = ('Without transition enforcement, platform admission accepts a cross-trust request while '
 'the modeled record is quarantined')
BLOCK_CLAIM = ('The modeled reset alone does not release quarantine and workload submitters cannot '
 'edit the platform record')
PASS_CLAIM = ('The matching reviewed transition permits the workload while a mismatched or later '
 'transition is denied')
MISMATCH_KEY = 'transition'
EVIDENCE = 'sanitization-release-observations.json'


def pod(name, fields):
    metadata = {"name": name, "annotations": {ANNOTATION + key: value for key, value in fields.items()}}
    return {"apiVersion": "v1", "kind": "Pod", "metadata": metadata,
            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "fixture", "image": IMAGE,
                                     "command": ["python", "-c", "import time; time.sleep(145)"],
                                     "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                                                   "limits": {"cpu": "100m", "memory": "40Mi"}},
                                     "securityContext": {"readOnlyRootFilesystem": True,
                                                         "allowPrivilegeEscalation": False,
                                                         "capabilities": {"drop": ["ALL"]}}}]}}


def install(lab):
    api = "admissionregistration.k8s.io/v1"
    matches = [f"'{ANNOTATION}{key}' in object.metadata.annotations && "
               f"object.metadata.annotations['{ANNOTATION}{key}'] == params.data['{key}']"
               for key in MATCHED]
    requirements = ["params != null", "has(params.data)", "params.data['state'] == 'approved'",
                    "params.data['workload'] == object.metadata.name", "has(object.metadata.annotations)"]
    expression = " && ".join(requirements + matches + RECORD_RULES)
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail", "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
                         "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                                "operations": ["CREATE"], "resources": ["pods"]}]},
                         "matchConditions": [{"name": "owned-fixture-scope",
                                              "expression": "object.metadata.name.startsWith('guarded-')"}],
                         "validations": [{"expression": expression, "message": REASON}]}})
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"],
                         "paramRef": {"name": PARAMETER, "namespace": NAMESPACE, "parameterNotFoundAction": "Deny"},
                         "matchResources": {"namespaceSelector": {"matchLabels": {"fixture.example/platform": "true"}}}}})


def replace_record(lab, fields):
    patch = [{"op": "replace", "path": "/data", "value": fields}]
    lab.kubectl("patch", "configmap", PARAMETER, "--type=json", "-p", json.dumps(patch))


def denied(response):
    return response.returncode != 0 and REASON in response.stderr


def allow_submitter(lab):
    rbac = "rbac.authorization.k8s.io"
    lab.create({"apiVersion": f"{rbac}/v1", "kind": "Role", "metadata": {"name": "fixture-submit"},
                "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]},
                          {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [PARAMETER], "verbs": ["get"]}]})
    lab.create({"apiVersion": f"{rbac}/v1", "kind": "RoleBinding", "metadata": {"name": "fixture-submit"},
                "roleRef": {"apiGroup": rbac, "kind": "Role", "name": "fixture-submit"},
                "subjects": [{"apiGroup": rbac, "kind": "User", "name": SUBMITTER}]})


def submit(lab, manifest, *, dry_run=True):
    flags = ["--dry-run=server"] if dry_run else []
    return lab.kubectl("--as", SUBMITTER, "create", "-f", "-", "-o", "json", *flags,
                       payload=json.dumps(manifest), allow_failure=True)


def observe(lab, manifest, *, reject):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        response = submit(lab, manifest)
        if reject and denied(response):
            return True
        if not reject and response.returncode == 0:
            return True
        time.sleep(0.4)
    lab.block("The admission policy did not produce the expected decision")


def submitter_can_edit_record(lab):
    evaluation = lab.create({"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview",
                             "spec": {"user": SUBMITTER, "groups": ["system:authenticated"],
                                      "resourceAttributes": {"namespace": NAMESPACE, "name": PARAMETER,
                                                             "resource": "configmaps", "verb": "patch"}}})["status"]
    if evaluation.get("evaluationError"):
        lab.block("The owner-versus-submitter check could not evaluate authorization")
    return evaluation.get("allowed", False)


def run(lab):
    lab.kubectl("label", "namespace", NAMESPACE, "fixture.example/platform=true", "pod-security.kubernetes.io/enforce=restricted")
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": PARAMETER}, "data": INITIAL_RECORD})
    allow_submitter(lab)
    manifest = pod(WORKLOAD, APPROVED_FIELDS)
    before = observe(lab, manifest, reject=False)
    lab.check("red", PRE_CLAIM, before, {"admitted_without_enforcement": before})

    install(lab)
    gated = observe(lab, manifest, reject=True)
    replace_record(lab, dict(APPROVED_RECORD, **{'evidence-id': ''}))
    incomplete_denied = observe(lab, manifest, reject=True)
    permissions_denied = not submitter_can_edit_record(lab)
    lab.check("green", BLOCK_CLAIM, gated and incomplete_denied and permissions_denied,
              {"initial_record_denied": gated, "incomplete_approved_record_denied": incomplete_denied, "fixture_submitter_cannot_patch_record": permissions_denied})

    replace_record(lab, APPROVED_RECORD)
    approved = observe(lab, manifest, reject=False)
    mismatched = dict(APPROVED_FIELDS, **{MISMATCH_KEY: "unapproved-fixture"})
    mismatch = denied(submit(lab, pod(WORKLOAD, mismatched)))
    if submit(lab, manifest, dry_run=False).returncode:
        lab.block("The approved fixture Pod could not be submitted")
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{WORKLOAD}", "--timeout=60s", timeout=70)
    live = json.loads(lab.kubectl("get", "pod", WORKLOAD, "-o", "json").stdout)
    running = live["status"]["phase"] == "Running"
    lab.kubectl("delete", "pod", WORKLOAD, "--grace-period=1", "--wait=true")
    replace_record(lab, CLOSED_RECORD)
    future_denied = observe(lab, manifest, reject=True)
    lab.check("positive", PASS_CLAIM, approved and mismatch and running and future_denied,
              {"authorized_workload_ran": running, "mismatched_request_denied": mismatch,
               "reopened_request_denied_after_closure": future_denied})
    result = {"record_is_synthetic": True, "approved_record": APPROVED_RECORD, "initial_record_denied": gated,
              "fixture_submitter_cannot_patch_record": permissions_denied, "incomplete_approved_record_denied": incomplete_denied,
              "approved_workload_ran": running,
              "mismatched_request_denied": mismatch, "later_request_denied": future_denied}
    (lab.evidence / EVIDENCE).write_text(json.dumps(result, indent=2) + "\n")
