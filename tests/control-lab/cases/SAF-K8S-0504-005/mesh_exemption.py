"""Case-only native admission gate for the inert Istio opt-out Pod."""

import copy
import json
import time


API_GROUP = "saf-lab.example"
API_VERSION = "v1alpha1"
KIND = "MeshExemption"
CRD_NAME = "meshexemptions." + API_GROUP
RECORD_NAME = "saf-0504-005-mesh-exemption"
POLICY_NAME = "saf-0504-005-optout-exception"
BINDING_NAME = POLICY_NAME
POD_NAME = "saf-0504-005-selective-optout"
NAMESPACE = "saf-test"
EXPIRES_ON = "2099-12-31"
COMPENSATION = "inert-fixture-no-network-path"
PURPOSE = "non-networked-optout-reference"

ANNOTATIONS = {
    "saf-k8s.example/mesh-exemption-id": RECORD_NAME,
    "saf-k8s.example/mesh-risk-owner": "fixture-risk-owner",
    "saf-k8s.example/mesh-approved-by": "fixture-security-reviewer",
    "saf-k8s.example/mesh-justification": "inert-sidecar-injection-policy-test",
    "saf-k8s.example/mesh-compensating-control": COMPENSATION,
    "saf-k8s.example/mesh-expires-on": EXPIRES_ON,
    "saf-k8s.example/mesh-review-id": "fixture-review-0504-005",
}


def _crd():
    return {
        "apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
        "metadata": {"name": CRD_NAME},
        "spec": {
            "group": API_GROUP, "scope": "Namespaced",
            "names": {"plural": "meshexemptions", "singular": "meshexemption",
                      "kind": KIND, "shortNames": ["meshx"]},
            "versions": [{
                "name": API_VERSION, "served": True, "storage": True,
                "schema": {"openAPIV3Schema": {
                    "type": "object", "required": ["spec"],
                    "properties": {"spec": {
                        "type": "object",
                        "required": ["approvalState", "exceptionId", "workloadNamespace",
                                      "workloadName", "fixturePurpose", "riskOwner", "approvedBy",
                                      "justification", "compensatingControls", "expiresOn", "reviewId"],
                        "properties": {
                            "approvalState": {"type": "string", "enum": ["pending", "approved", "expired"]},
                            "exceptionId": {"type": "string", "minLength": 1},
                            "workloadNamespace": {"type": "string", "minLength": 1},
                            "workloadName": {"type": "string", "minLength": 1},
                            "fixturePurpose": {"type": "string", "minLength": 1},
                            "riskOwner": {"type": "string", "minLength": 1},
                            "approvedBy": {"type": "string", "minLength": 1},
                            "justification": {"type": "string", "minLength": 1},
                            "compensatingControls": {"type": "array", "minItems": 1,
                                "items": {"type": "string", "minLength": 1}},
                            "expiresOn": {"type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"},
                            "reviewId": {"type": "string", "minLength": 1},
                        },
                    }},
                }},
            }],
        },
    }


def _policy(fixture_pod):
    expression = r'''!has(object.metadata.labels) ||
!('sidecar.istio.io/inject' in object.metadata.labels) ||
object.metadata.labels['sidecar.istio.io/inject'] != 'false' ||
(
  request.namespace == 'saf-test' &&
  object.metadata.name == 'saf-0504-005-selective-optout' &&
  object.metadata.labels['saf-k8s.example/fixture-purpose'] == params.spec.fixturePurpose &&
  params.spec.fixturePurpose == 'non-networked-optout-reference' &&
  object.spec.containers.size() == 1 &&
  object.spec.containers.all(c, !has(c.ports)) &&
  has(object.metadata.annotations) &&
  object.metadata.annotations['saf-k8s.example/mesh-exemption-id'] == params.spec.exceptionId &&
  object.metadata.annotations['saf-k8s.example/mesh-risk-owner'] == params.spec.riskOwner &&
  object.metadata.annotations['saf-k8s.example/mesh-approved-by'] == params.spec.approvedBy &&
  object.metadata.annotations['saf-k8s.example/mesh-justification'] == params.spec.justification &&
  object.metadata.annotations['saf-k8s.example/mesh-compensating-control'] == params.spec.compensatingControls[0] &&
  object.metadata.annotations['saf-k8s.example/mesh-expires-on'] == params.spec.expiresOn &&
  object.metadata.annotations['saf-k8s.example/mesh-review-id'] == params.spec.reviewId &&
  params.spec.approvalState == 'approved' &&
  params.spec.exceptionId == 'saf-0504-005-mesh-exemption' &&
  params.spec.workloadNamespace == request.namespace &&
  params.spec.workloadName == object.metadata.name &&
  params.spec.riskOwner == 'fixture-risk-owner' &&
  params.spec.approvedBy == 'fixture-security-reviewer' &&
  params.spec.justification == 'inert-sidecar-injection-policy-test' &&
  params.spec.compensatingControls == ['inert-fixture-no-network-path'] &&
  params.spec.expiresOn == '2099-12-31' &&
  params.spec.reviewId == 'fixture-review-0504-005'
)'''
    container = fixture_pod["spec"]["containers"][0]
    exact_fixture = (
        "object.spec.containers.size() == 1 && object.spec.containers.all(c, "
        "c.image == " + json.dumps(container["image"]) +
        " && c.command == " + json.dumps(container["command"]) +
        " && (!has(c.args) || c.args.size() == 0))"
        " && (!has(object.spec.initContainers) || object.spec.initContainers.size() == 0)"
        " && (!has(object.spec.ephemeralContainers) || object.spec.ephemeralContainers.size() == 0)"
        " && (!has(object.spec.hostNetwork) || !object.spec.hostNetwork)"
        " && has(object.spec.automountServiceAccountToken)"
        " && !object.spec.automountServiceAccountToken"
    )
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": POLICY_NAME},
        "spec": {
            "failurePolicy": "Fail",
            "paramKind": {"apiVersion": API_GROUP + "/" + API_VERSION, "kind": KIND},
            "matchConstraints": {"resourceRules": [{
                "apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"],
                "resources": ["pods"], "scope": "Namespaced",
            }]},
            "validations": [
                {"expression": "!has(object.metadata.labels) || !('sidecar.istio.io/inject' in object.metadata.labels) || object.metadata.labels['sidecar.istio.io/inject'] != 'false' || params.spec.approvalState == 'approved'",
                 "message": "optout-record-state-must-be-approved"},
                {"expression": "!has(object.metadata.labels) || !('sidecar.istio.io/inject' in object.metadata.labels) || object.metadata.labels['sidecar.istio.io/inject'] != 'false' || (params.spec.workloadNamespace == request.namespace && params.spec.workloadName == object.metadata.name)",
                 "message": "optout-record-workload-scope-mismatch"},
                {"expression": exact_fixture, "message": "optout-record-fixture-spec-mismatch"},
                {"expression": expression,
                 "message": "A sidecar injection opt-out requires the exact approved inert-fixture MeshExemption record."},
            ],
        },
    }


def _binding():
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": BINDING_NAME},
        "spec": {
            "policyName": POLICY_NAME,
            "paramRef": {"name": RECORD_NAME, "namespace": NAMESPACE,
                         "parameterNotFoundAction": "Deny"},
            "matchResources": {
                "namespaceSelector": {"matchLabels": {"saf-k8s.example/mesh-optout-gate": "enabled"}},
                "objectSelector": {"matchLabels": {"sidecar.istio.io/inject": "false"}},
            },
            "validationActions": ["Deny"],
        },
    }


def _record(*, approval_state, workload_name=POD_NAME):
    return {
        "apiVersion": API_GROUP + "/" + API_VERSION,
        "kind": KIND,
        "metadata": {"name": RECORD_NAME, "namespace": NAMESPACE,
                     "labels": {"saf-k8s.example/fixture": "mesh-exemption"}},
        "spec": {
            "approvalState": approval_state,
            "exceptionId": RECORD_NAME,
            "workloadNamespace": NAMESPACE,
            "workloadName": workload_name,
            "fixturePurpose": PURPOSE,
            "riskOwner": "fixture-risk-owner",
            "approvedBy": "fixture-security-reviewer",
            "justification": "inert-sidecar-injection-policy-test",
            "compensatingControls": [COMPENSATION],
            "expiresOn": EXPIRES_ON,
            "reviewId": "fixture-review-0504-005",
        },
    }


def _apply(kubectl, lab, obj, *, timeout=60):
    kubectl(lab, "apply", "-f", "-", payload=json.dumps(obj), timeout=timeout)


def _dry_run(kubectl, lab, obj):
    return kubectl(lab, "create", "-f", "-", "--dry-run=server", "-o", "name",
                   payload=json.dumps(obj), timeout=25, allow_failure=True)


def _dryrun_outcome(kubectl, lab, obj, *, denied_message=None, seconds=30):
    """Wait for one exact server-side admission outcome and its own diagnostic."""
    deadline = time.monotonic() + seconds
    last = ""
    while time.monotonic() < deadline:
        result = _dry_run(kubectl, lab, obj)
        last = (result.stderr + "\n" + result.stdout).lower()
        if denied_message is None:
            if result.returncode == 0:
                return True
        elif (result.returncode != 0 and denied_message.lower() in last
              and (POLICY_NAME.lower() in last or BINDING_NAME.lower() in last)):
            return True
        time.sleep(0.5)
    return False


def _policy_accepted(kubectl, lab):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        result = kubectl(lab, "get", "validatingadmissionpolicy", POLICY_NAME,
                         "-o", "json", timeout=15, allow_failure=True)
        if result.returncode == 0:
            try:
                document = json.loads(result.stdout)
            except json.JSONDecodeError:
                document = {}
            metadata = document.get("metadata", {})
            status = document.get("status", {})
            # Match the published 0901-006 VAP preflight: wait for this exact
            # generation to be type-checked, not an optional Accepted condition.
            if (metadata.get("generation") == status.get("observedGeneration")
                    and "typeChecking" in status):
                return True
        time.sleep(0.5)
    return False


def _candidate_pod(source_pod):
    pod = copy.deepcopy(source_pod)
    pod["metadata"]["name"] = POD_NAME
    pod["metadata"]["namespace"] = NAMESPACE
    pod["metadata"].setdefault("labels", {})["sidecar.istio.io/inject"] = "false"
    pod["metadata"]["labels"]["saf-k8s.example/fixture-purpose"] = PURPOSE
    pod["metadata"]["annotations"] = dict(pod["metadata"].get("annotations", {}))
    pod["metadata"]["annotations"].update(ANNOTATIONS)
    return pod


def prepare(lab, bare_pod, *, kubectl):
    kubectl(lab, "label", "namespace", NAMESPACE,
            "saf-k8s.example/mesh-optout-gate=enabled", "--overwrite", timeout=20)
    _apply(kubectl, lab, _crd())
    kubectl(lab, "wait", "--for=condition=Established", "crd/" + CRD_NAME,
            "--timeout=60s", timeout=70)
    _apply(kubectl, lab, _policy(bare_pod))
    if not _policy_accepted(kubectl, lab):
        lab.block("The native mesh opt-out ValidatingAdmissionPolicy was not Accepted")
    _apply(kubectl, lab, _binding())
    kubectl(lab, "get", "validatingadmissionpolicybinding", BINDING_NAME,
            "-o", "json", timeout=15)

    bare = copy.deepcopy(bare_pod)
    bare["metadata"]["name"] = POD_NAME
    bare["metadata"]["namespace"] = NAMESPACE
    bare["metadata"]["labels"]["sidecar.istio.io/inject"] = "false"
    bare["metadata"]["labels"]["saf-k8s.example/fixture-purpose"] = PURPOSE
    bare_denied = _dryrun_outcome(
        kubectl, lab, bare, denied_message="param", seconds=30)

    approved_pod = _candidate_pod(bare_pod)
    _apply(kubectl, lab, _record(approval_state="expired"))
    expired_denied = _dryrun_outcome(
        kubectl, lab, approved_pod, denied_message="optout-record-state-must-be-approved")

    _apply(kubectl, lab, _record(approval_state="approved", workload_name="different-inert-pod"))
    wrong_scope_denied = _dryrun_outcome(
        kubectl, lab, approved_pod, denied_message="optout-record-workload-scope-mismatch")

    _apply(kubectl, lab, _record(approval_state="approved"))
    approved_admitted = _dryrun_outcome(kubectl, lab, approved_pod)
    changed_pod = copy.deepcopy(approved_pod)
    changed_pod["spec"]["containers"][0]["command"] = ["python", "-B", "-c", "pass"]
    changed_pod_denied = _dryrun_outcome(
        kubectl, lab, changed_pod, denied_message="optout-record-fixture-spec-mismatch")
    if not all((bare_denied, expired_denied, wrong_scope_denied, approved_admitted, changed_pod_denied)):
        lab.block("The mesh exception gate did not deny missing, expired-state, and wrong-scope records or admit the exact fixture record")
    return {
        "approved_pod": approved_pod,
        "normalized": {"bare_optout_without_record_denied": bare_denied,
                       "expired_state_record_denied": expired_denied,
                       "wrong_workload_binding_denied": wrong_scope_denied,
                       "changed_inert_command_denied": changed_pod_denied,
                       "exact_approved_fixture_record_admitted": approved_admitted,
                       "parameter_missing_action_deny": True,
                       "vap_failure_policy_fail": True},
    }


def finish(lab, gate, pod, pod_json, meshed_pod, rows, authenticated, assert_check):
    spec = pod_json.get("spec", {})
    labels = pod_json.get("metadata", {}).get("labels", {})
    containers = spec.get("containers", [])
    inert = (pod_json.get("metadata", {}).get("name") == POD_NAME
             and pod_json.get("metadata", {}).get("namespace") == NAMESPACE
             and labels.get("saf-k8s.example/fixture-purpose") == PURPOSE
             and len(containers) == 1 and not containers[0].get("ports")
             and containers[0].get("command") == pod["spec"]["containers"][0].get("command")
             and containers[0].get("image") == pod["spec"]["containers"][0].get("image")
             and not spec.get("initContainers") and not spec.get("ephemeralContainers")
             and not spec.get("hostNetwork")
             and spec.get("automountServiceAccountToken") is False)
    no_proxy = sum(container.get("name") == "istio-proxy"
                    for container in [*containers, *spec.get("initContainers", [])]) == 0
    mesh_containers = [*meshed_pod.get("spec", {}).get("containers", []),
                       *meshed_pod.get("spec", {}).get("initContainers", [])]
    mesh_route_retained = (sum(container.get("name") == "istio-proxy"
                               for container in mesh_containers) == 1
                           and authenticated and len(rows) == 3
                           and all(row.get("status") == 200 for row in rows))
    passed = all(gate["normalized"].values()) and inert and no_proxy and mesh_route_retained
    assert_check(
        lab, "positive",
        "Native admission requires a complete scoped exception record for only the inert sidecar opt-out Pod",
        passed,
        {**gate["normalized"], "admitted_pod_is_exact_nonnetworked_fixture": inert,
         "admitted_optout_has_no_proxy": no_proxy,
         "separate_meshed_authenticated_route_remains_active": mesh_route_retained,
         "compensation_scope": "inert no-network-path test Pod only; no production transport compensation proved"},
    )
