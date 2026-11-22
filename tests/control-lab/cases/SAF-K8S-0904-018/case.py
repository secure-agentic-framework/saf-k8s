"""Enforce one synthetic workflow rollback through Kubernetes admission and RBAC."""
import hashlib
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
VERSIONS_FILE = HERE / "fixtures" / "workflow_versions.json"
APPROVAL_FILE = HERE / "fixtures" / "approved_transition.json"
NAMESPACE = "saf-test"
OPERATOR = "system:serviceaccount:saf-test:saf-workflow-operator"
POLICY = "saf-workflow-rollback-approval"
BINDING = "saf-workflow-rollback-approval"
APPROVAL = "saf-workflow-approval-v1"
V1 = "saf-workflow-v1"
V2 = "saf-workflow-v2"
V3 = "saf-workflow-v3"
ACTIVE = "saf-workflow-active"
DENY_MESSAGE = "workflow rollback must match the approved source, target identity, digest, and change ID"
SCOPE = (
    "One disposable Kind Kubernetes v1.36.1 cluster and the runner's saf-test namespace. This "
    "case retains the mutable-to-immutable ConfigMap and scoped-RBAC version checks, and adds a "
    "native admissionregistration.k8s.io/v1 ValidatingAdmissionPolicy with a namespaced core/v1 "
    "ConfigMap parameter and ValidatingAdmissionPolicyBinding. The policy matches only UPDATEs "
    "to the saf-test ConfigMap named saf-workflow-active and enforces one exact CAS-style "
    "v2-to-v1 rollback using the old pointer state, target name/UID/digest, and change ID. "
    "Approval values and workflow strings are synthetic inert fixtures. No Pods or workflow "
    "executions are created. Production approval authority, policy administration, audit "
    "retention, platform integration, and privileged administrator paths remain untested."
)


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _cm(name, data, *, immutable=False):
    return {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": name, "labels": {"saf-lab.example/control": "SAF-K8S-0904-018"}},
        "immutable": immutable, "data": data,
    }


def _get_cm(lab, name, *, operator=False):
    args = ("get", "configmap", name, "-o", "json")
    result = _as_operator(lab, *args) if operator else lab.kubectl(*args)
    return json.loads(result.stdout)


def _as_operator(lab, *args, **kwargs):
    return lab.kubectl("--as", OPERATOR, *args, **kwargs)


def _role(rules):
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": "saf-workflow-operator"}, "rules": rules,
    }


def _binding_role():
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": "saf-workflow-operator"},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                    "name": "saf-workflow-operator"},
        "subjects": [{"kind": "ServiceAccount", "name": "saf-workflow-operator",
                      "namespace": NAMESPACE}],
    }


def _patch(lab, name, patch, *, operator=True, dry_run=False, allow_failure=False):
    args = ("patch", "configmap", name, "--type=merge", "-p",
            json.dumps(patch, sort_keys=True))
    if dry_run:
        args += ("--dry-run=server",)
    args += ("-o", "json")
    result = _as_operator(lab, *args, allow_failure=allow_failure) if operator else lab.kubectl(
        *args, allow_failure=allow_failure)
    return result


def _policy_object():
    fields = ["approval_status", "change_id", "from_version", "from_sha256", "from_uid",
              "to_version", "to_sha256", "to_uid"]
    presence = " && ".join(f'"{field}" in params.data' for field in fields)
    expression = (
        "params != null && has(params.immutable) && params.immutable == true && "
        "has(params.data) && has(oldObject.data) && has(object.data) && "
        f"{presence} && "
        'params.data["approval_status"] == "approved" && '
        'oldObject.data["workflow_version"] == params.data["from_version"] && '
        'oldObject.data["workflow_sha256"] == params.data["from_sha256"] && '
        'oldObject.data["workflow_uid"] == params.data["from_uid"] && '
        'object.data["workflow_version"] == params.data["to_version"] && '
        'object.data["workflow_sha256"] == params.data["to_sha256"] && '
        'object.data["workflow_uid"] == params.data["to_uid"] && '
        'object.data["change_id"] == params.data["change_id"]'
    )
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": POLICY},
        "spec": {
            "failurePolicy": "Fail",
            "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
            "matchConstraints": {"resourceRules": [{
                "apiGroups": [""], "apiVersions": ["v1"],
                "operations": ["UPDATE"], "resources": ["configmaps"],
            }]},
            "matchConditions": [{
                "name": "approved-pointer-in-saf-test",
                "expression": f'request.namespace == "{NAMESPACE}" && object.metadata.name == "{ACTIVE}"',
            }],
            "validations": [{"expression": expression, "message": DENY_MESSAGE,
                             "reason": "Forbidden"}],
        },
    }


def _policy_binding():
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": BINDING},
        "spec": {
            "policyName": POLICY,
            "paramRef": {"name": APPROVAL, "namespace": NAMESPACE,
                         "parameterNotFoundAction": "Deny"},
            "validationActions": ["Deny"],
        },
    }


def _check_policy_ready(lab):
    deadline = time.monotonic() + 20
    last = None
    while time.monotonic() < deadline:
        last = json.loads(lab.kubectl("get", "validatingadmissionpolicy", POLICY, "-o", "json").stdout)
        checking = last.get("status", {}).get("typeChecking")
        if checking is not None:
            warnings = checking.get("expressionWarnings", [])
            (lab.evidence / "admission-policy-status.raw.json").write_text(
                json.dumps(last, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            if warnings:
                lab.block("ValidatingAdmissionPolicy has CEL type-check warnings; stopping before probes")
            return True
        time.sleep(0.25)
    if last is not None:
        (lab.evidence / "admission-policy-status.raw.json").write_text(
            json.dumps(last, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lab.block("Kubernetes did not publish ValidatingAdmissionPolicy type-check status before probes")


def _write_raw(lab, filename, value):
    (lab.evidence / filename).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                                         encoding="utf-8")


def run(lab):
    versions_fixture = json.loads(VERSIONS_FILE.read_text(encoding="utf-8"))
    approval_fixture = json.loads(APPROVAL_FILE.read_text(encoding="utf-8"))
    versions = versions_fixture.get("versions", {})
    if set(versions) != {V1, V2, V3}:
        lab.block("Workflow fixture must contain exactly v1, v2, and v3")
    for name, row in versions.items():
        if not isinstance(row.get("content"), str) or _sha(row["content"]) != row.get("sha256"):
            lab.block(f"Fixed inert content digest mismatch for {name}")
    if (approval_fixture.get("approval_status") != "approved"
            or approval_fixture.get("from_version") != V2
            or approval_fixture.get("to_version") != V1
            or approval_fixture.get("from_sha256") != versions[V2]["sha256"]
            or approval_fixture.get("to_sha256") != versions[V1]["sha256"]
            or approval_fixture.get("change_id") != "fixture-rollback-v2-to-v1"
            or approval_fixture.get("approved_by") != ["fixture-ml-platform-owner", "fixture-security-reviewer"]):
        lab.block("Fixed approval fixture does not bind the exact inert v2-to-v1 change")

    lab.create({"apiVersion": "v1", "kind": "ServiceAccount",
                "metadata": {"name": "saf-workflow-operator"}})
    broad_role = _role([{"apiGroups": [""], "resources": ["configmaps"],
                         "verbs": ["get", "list", "create", "patch", "update", "delete"]}])
    lab.create(broad_role)
    lab.create(_binding_role())

    # Measure the same operator's initial version-modification and deletion capabilities.
    tampered_content = "pipeline: inert-fixture\nsteps:\n  - name: changed-before-policy\n    actions: []\n"
    lab.create(_cm(V1, {"workflow.yaml": versions[V1]["content"]}))
    initial_patch = _patch(lab, V1, {"data": {"workflow.yaml": tampered_content}})
    changed_v1 = json.loads(initial_patch.stdout)
    initial_patch_ok = (_sha(changed_v1["data"]["workflow.yaml"]) == _sha(tampered_content)
                        and changed_v1["immutable"] is False)
    if not initial_patch_ok:
        lab.block("Broad-role version patch did not change the mutable fixture through the API")
    delete_dry_run = _as_operator(lab, "delete", "configmap", V1, "--dry-run=server", allow_failure=True)
    after_delete_dry_run = _get_cm(lab, V1)
    delete_dry_run_ok = (delete_dry_run.returncode == 0
                         and after_delete_dry_run["metadata"]["uid"] == changed_v1["metadata"]["uid"]
                         and _sha(after_delete_dry_run["data"]["workflow.yaml"]) == _sha(tampered_content))

    # Restore exact fixture content, then make retained versions immutable.
    seed_v1 = _get_cm(lab, V1)
    seed_v1["data"] = {"workflow.yaml": versions[V1]["content"]}
    seed_v1["immutable"] = True
    lab.kubectl("replace", "-f", "-", payload=json.dumps(seed_v1))
    lab.create(_cm(V2, {"workflow.yaml": versions[V2]["content"]}, immutable=True))
    retained_v1 = _get_cm(lab, V1)
    retained_v2 = _get_cm(lab, V2)
    v1_ready = (retained_v1.get("immutable") is True
                and _sha(retained_v1["data"]["workflow.yaml"]) == versions[V1]["sha256"])
    v2_ready = (retained_v2.get("immutable") is True
                and _sha(retained_v2["data"]["workflow.yaml"]) == versions[V2]["sha256"])
    if not (delete_dry_run_ok and v1_ready and v2_ready):
        lab.block("Broad-role delete dry-run or immutable retained-version readback was unexpected")
    immutable_patch = _patch(lab, V1, {"data": {"workflow.yaml": tampered_content}},
                             allow_failure=True)
    immutable_error = immutable_patch.stderr + immutable_patch.stdout
    immutable_v1_after_probe = _get_cm(lab, V1)
    immutable_rejection_ok = (
        immutable_patch.returncode != 0 and "immutable" in immutable_error.lower()
        and immutable_v1_after_probe["immutable"] is True
        and _sha(immutable_v1_after_probe["data"]["workflow.yaml"]) == versions[V1]["sha256"]
    )
    if not immutable_rejection_ok:
        lab.block("Write-capable operator's patch to immutable v1 was not rejected for immutability")
    lab.check("red", "The operator can patch a mutable version and the pre-policy server-side delete dry-run is allowed",
              initial_patch_ok and delete_dry_run_ok and immutable_rejection_ok,
              {"mutable_version_patch_succeeded": initial_patch_ok,
               "server_dry_run_delete_allowed": delete_dry_run_ok,
               "dry_run_preserved_version": True,
               "immutable_api_rejected_patch_under_write_capable_role": immutable_rejection_ok})

    active_data = {
        "workflow_version": V2, "workflow_sha256": versions[V2]["sha256"],
        "workflow_uid": retained_v2["metadata"]["uid"], "change_id": "fixture-initial-v2",
    }
    lab.create(_cm(ACTIVE, active_data))
    approval_data = {
        "approval_status": approval_fixture["approval_status"],
        "change_id": approval_fixture["change_id"],
        "from_version": approval_fixture["from_version"],
        "from_sha256": approval_fixture["from_sha256"],
        "from_uid": retained_v2["metadata"]["uid"],
        "to_version": approval_fixture["to_version"],
        "to_sha256": approval_fixture["to_sha256"],
        "to_uid": retained_v1["metadata"]["uid"],
        "approved_by": ",".join(approval_fixture["approved_by"]),
        "approved_at": approval_fixture["approved_at"],
    }
    approval_object = _cm(APPROVAL, approval_data, immutable=True)
    lab.create(approval_object)

    active_before_off = _get_cm(lab, ACTIVE)
    mismatch = {"metadata": {"resourceVersion": active_before_off["metadata"]["resourceVersion"]},
                "data": {"workflow_version": V1,
                         "workflow_sha256": versions[V1]["sha256"],
                         "workflow_uid": retained_v1["metadata"]["uid"],
                         "change_id": "fixture-unapproved-change"}}
    off_result = _patch(lab, ACTIVE, mismatch, dry_run=True, allow_failure=True)
    active_after_off = _get_cm(lab, ACTIVE)
    off_accepted_unchanged = (off_result.returncode == 0
                              and active_after_off["metadata"]["uid"] == active_before_off["metadata"]["uid"]
                              and active_after_off["metadata"]["resourceVersion"] == active_before_off["metadata"]["resourceVersion"]
                              and active_after_off["data"] == active_before_off["data"])
    if not off_accepted_unchanged:
        _write_raw(lab, "governed-rollback.raw.json", {
            "off_response": {"returncode": off_result.returncode, "stdout": off_result.stdout,
                             "stderr": off_result.stderr},
            "active_before_off": active_before_off, "active_after_off": active_after_off,
            "approval_param": approval_data, "retained_v1": retained_v1, "retained_v2": retained_v2,
        })
        lab.block("Off-phase mismatch dry-run failed or changed the active pointer")
    lab.check("red", "Before admission policy is bound, the same mismatched rollback patch is accepted by server dry-run and persists no change",
              off_accepted_unchanged,
              {"server_dry_run_accepted": True, "pointer_unchanged_after_dry_run": True})

    lab.create(_policy_object())
    lab.create(_policy_binding())
    _check_policy_ready(lab)
    scoped_role = _role([
        {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "list", "create"]},
        {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [ACTIVE],
         "verbs": ["patch", "update"]},
    ])
    lab.kubectl("apply", "-f", "-", payload=json.dumps(scoped_role))

    version_patch_scoped = _patch(lab, V1, {"data": {"workflow.yaml": tampered_content}},
                                  allow_failure=True)
    version_delete_scoped = _as_operator(lab, "delete", "configmap", V1, allow_failure=True)
    version_same_name_create = _as_operator(
        lab, "create", "-f", "-", "-o", "json",
        payload=json.dumps(_cm(V1, {"workflow.yaml": versions[V3]["content"]}, immutable=True)),
        allow_failure=True)
    version_errors = [version_patch_scoped.stderr + version_patch_scoped.stdout,
                      version_delete_scoped.stderr + version_delete_scoped.stdout]
    version_scoped_ok = (
        version_patch_scoped.returncode != 0 and version_delete_scoped.returncode != 0
        and all("forbidden" in error.lower() for error in version_errors)
        and version_same_name_create.returncode != 0
        and ("alreadyexists" in version_same_name_create.stderr.lower()
             or "already exists" in version_same_name_create.stderr.lower())
        and _sha(_get_cm(lab, V1)["data"]["workflow.yaml"]) == versions[V1]["sha256"]
    )
    if not version_scoped_ok:
        lab.block("Narrow Role did not deny version patch/delete and preserve occupied name")

    # Confirm the admission requester can read its bound core/v1 parameter.
    approval_read = _get_cm(lab, APPROVAL, operator=True)
    approval_read_ok = (approval_read.get("immutable") is True
                        and approval_read.get("data") == approval_data)
    if not approval_read_ok:
        lab.block("Requesting operator identity could not read the immutable approval parameter")
    approval_patch = _as_operator(lab, "patch", "configmap", APPROVAL, "--type=merge", "-p",
                                  json.dumps({"data": {"change_id": "fixture-altered-change"}}),
                                  allow_failure=True)
    approval_update_body = dict(approval_read)
    approval_update_body["data"] = {**approval_data, "change_id": "fixture-altered-change"}
    approval_update = _as_operator(lab, "replace", "-f", "-", payload=json.dumps(approval_update_body),
                                   allow_failure=True)
    approval_delete = _as_operator(lab, "delete", "configmap", APPROVAL, allow_failure=True)
    protected_errors = [approval_patch.stderr + approval_patch.stdout,
                        approval_update.stderr + approval_update.stdout,
                        approval_delete.stderr + approval_delete.stdout]
    approval_protected = (approval_patch.returncode != 0 and approval_update.returncode != 0
                          and approval_delete.returncode != 0
                          and all("forbidden" in err.lower() for err in protected_errors))
    param_still_present = _get_cm(lab, APPROVAL).get("data") == approval_data
    if not (approval_protected and param_still_present):
        lab.block("Operator could modify/delete the approval parameter or it changed unexpectedly")

    # Repeat the exact off-phase request. Any unrelated failure is a blocked fixture, not policy proof.
    deadline = time.monotonic() + 15
    while True:
        on_result = _patch(lab, ACTIVE, mismatch, dry_run=True, allow_failure=True)
        if on_result.returncode != 0 or time.monotonic() >= deadline:
            break
        time.sleep(0.3)
    on_error = on_result.stderr + on_result.stdout
    named_policy = f"ValidatingAdmissionPolicy '{POLICY}'" in on_error
    named_binding = f"binding '{BINDING}'" in on_error
    exact_reason = "(Forbidden)" in on_error
    exact_message = DENY_MESSAGE in on_error
    if on_result.returncode and not (named_policy and named_binding and exact_reason and exact_message):
        _write_raw(lab, "governed-rollback.raw.json", {
            "off_response": {"returncode": off_result.returncode, "stdout": off_result.stdout,
                             "stderr": off_result.stderr},
            "on_response": {"returncode": on_result.returncode, "stdout": on_result.stdout,
                            "stderr": on_result.stderr},
            "active_before_off": active_before_off, "active_after_off": active_after_off,
            "active_after_on": _get_cm(lab, ACTIVE), "policy": _policy_object(),
            "binding": _policy_binding(), "approval_param": _get_cm(lab, APPROVAL),
        })
        lab.block("On-phase rollback rejection was unrelated to the named policy or exact message")
    active_after_on = _get_cm(lab, ACTIVE)
    denied_unchanged = (on_result.returncode != 0
                        and active_after_on["metadata"]["uid"] == active_before_off["metadata"]["uid"]
                        and active_after_on["metadata"]["resourceVersion"] == active_before_off["metadata"]["resourceVersion"]
                        and active_after_on["data"] == active_before_off["data"])
    lab.check("green", "The bound admission policy denies the identical mismatched rollback with its exact Forbidden reason and message",
              denied_unchanged and named_policy and named_binding and exact_reason and exact_message,
              {"mismatched_patch_denied": on_result.returncode != 0,
               "named_policy_rejection": named_policy,
               "named_binding_rejection": named_binding,
               "forbidden_reason": exact_reason,
               "exact_approval_message": exact_message,
               "pointer_unchanged_after_denial": denied_unchanged})
    lab.check("green", "The requesting identity can read but cannot patch, replace, or delete the immutable approval parameter",
              approval_read_ok and approval_protected and param_still_present,
              {"parameter_read_succeeded": approval_read_ok,
               "patch_denied": approval_patch.returncode != 0,
               "update_denied": approval_update.returncode != 0,
               "delete_denied": approval_delete.returncode != 0,
               "parameter_still_present": param_still_present})
    lab.check("green", "The narrowed Role denies retained-version patch/delete and the occupied version name cannot be recreated",
              version_scoped_ok,
              {"retained_version_patch_denied": version_patch_scoped.returncode != 0,
               "retained_version_delete_denied": version_delete_scoped.returncode != 0,
               "same_name_create_conflicted": version_same_name_create.returncode != 0,
               "retained_version_content_unchanged": True})

    # Positive control: create a new immutable version under scoped RBAC.
    v3_result = _as_operator(lab, "create", "-f", "-", "-o", "json",
                              payload=json.dumps(_cm(V3, {"workflow.yaml": versions[V3]["content"]}, immutable=True)))
    created_v3 = json.loads(v3_result.stdout)
    distinct_version_ok = (created_v3.get("immutable") is True
                           and _sha(created_v3.get("data", {}).get("workflow.yaml", "")) == versions[V3]["sha256"])
    if not distinct_version_ok:
        lab.block("Operator could not create a distinct immutable version under the scoped Role")

    # Kubernetes checks the supplied resourceVersion as the CAS precondition; admission checks oldObject.
    active_for_rollback = _get_cm(lab, ACTIVE)
    approved_patch = {"metadata": {"resourceVersion": active_for_rollback["metadata"]["resourceVersion"]},
                      "data": {"workflow_version": V1,
                               "workflow_sha256": versions[V1]["sha256"],
                               "workflow_uid": retained_v1["metadata"]["uid"],
                               "change_id": approval_fixture["change_id"]}}
    approved_result = _patch(lab, ACTIVE, approved_patch, allow_failure=True)
    if approved_result.returncode:
        _write_raw(lab, "governed-rollback.raw.json", {
            "off_response": {"returncode": off_result.returncode, "stdout": off_result.stdout,
                             "stderr": off_result.stderr},
            "on_response": {"returncode": on_result.returncode, "stdout": on_result.stdout,
                            "stderr": on_result.stderr},
            "approved_response": {"returncode": approved_result.returncode,
                                  "stdout": approved_result.stdout, "stderr": approved_result.stderr},
            "active_for_rollback": active_for_rollback, "approved_patch": approved_patch,
            "approval_param": _get_cm(lab, APPROVAL), "retained_v1": _get_cm(lab, V1),
        })
        lab.block("Matching approved rollback was rejected; do not treat unrelated failures as enforcement")
    approved_response = json.loads(approved_result.stdout)
    active_after_rollback = _get_cm(lab, ACTIVE)
    retained_after_rollback = _get_cm(lab, V1)
    rollback_ok = (
        active_after_rollback.get("data") == approved_patch["data"]
        and active_after_rollback["metadata"]["uid"] == active_for_rollback["metadata"]["uid"]
        and active_after_rollback["metadata"]["resourceVersion"] != active_for_rollback["metadata"]["resourceVersion"]
        and approved_response.get("data") == approved_patch["data"]
        and retained_after_rollback.get("immutable") is True
        and retained_after_rollback["metadata"]["uid"] == retained_v1["metadata"]["uid"]
        and _sha(retained_after_rollback.get("data", {}).get("workflow.yaml", "")) == versions[V1]["sha256"]
    )
    _write_raw(lab, "governed-rollback.raw.json", {
        "off_response": {"returncode": off_result.returncode, "stdout": off_result.stdout,
                         "stderr": off_result.stderr},
        "on_response": {"returncode": on_result.returncode, "stdout": on_result.stdout,
                        "stderr": on_result.stderr},
        "approved_response": {"returncode": approved_result.returncode,
                              "stdout": approved_result.stdout, "stderr": approved_result.stderr},
        "active_before_off": active_before_off, "active_after_off": active_after_off,
        "active_after_denial": active_after_on, "active_for_rollback": active_for_rollback,
        "active_after_rollback": active_after_rollback,
        "approval_parameter_as_operator": approval_read,
        "approval_parameter_after_attempts": _get_cm(lab, APPROVAL),
        "approval_patch_response": {"returncode": approval_patch.returncode,
                                    "stdout": approval_patch.stdout, "stderr": approval_patch.stderr},
        "approval_replace_response": {"returncode": approval_update.returncode,
                                      "stdout": approval_update.stdout, "stderr": approval_update.stderr},
        "approval_delete_response": {"returncode": approval_delete.returncode,
                                     "stdout": approval_delete.stdout, "stderr": approval_delete.stderr},
        "retained_v1_before": retained_v1, "retained_v1_after": retained_after_rollback,
        "retained_v2": retained_v2, "created_v3": created_v3,
        "mutable_version_patch_response": {"returncode": initial_patch.returncode,
                                            "stdout": initial_patch.stdout, "stderr": initial_patch.stderr},
        "operator_delete_server_dry_run_stdout": delete_dry_run.stdout,
        "operator_delete_server_dry_run_stderr": delete_dry_run.stderr,
        "immutable_patch_response": {"returncode": immutable_patch.returncode,
                                      "stdout": immutable_patch.stdout, "stderr": immutable_patch.stderr},
        "scoped_version_patch_response": {"returncode": version_patch_scoped.returncode,
                                           "stdout": version_patch_scoped.stdout,
                                           "stderr": version_patch_scoped.stderr},
        "scoped_version_delete_response": {"returncode": version_delete_scoped.returncode,
                                            "stdout": version_delete_scoped.stdout,
                                            "stderr": version_delete_scoped.stderr},
        "same_name_create_response": {"returncode": version_same_name_create.returncode,
                                      "stdout": version_same_name_create.stdout,
                                      "stderr": version_same_name_create.stderr},
    })
    lab.check("positive", "Exact approved CAS rollback succeeds and the original immutable v1 content and UID remain present",
              distinct_version_ok and rollback_ok,
              {"new_immutable_version_allowed": distinct_version_ok,
               "approved_rollback_allowed": True,
               "active_pointer_targets_approved_version": rollback_ok,
               "retained_immutable_content_present": rollback_ok,
               "cas_resource_version_supplied": True,
               "resource_version_advanced": rollback_ok})
