"""Exercise privacy classification, scoped file and API reads, and log access on Kind."""
from datetime import datetime
import importlib.util
import json
import hashlib
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
PVC = "fixture-privacy-data"
CODE = "fixture-privacy-code"
INDEX = "fixture-approved-data-index"
OTHER = "fixture-other-data-index"
NS = "saf-test"
GROUP = 20100
PROCESSOR = "fixture-data-processor"
ALLOWED = "fixture-data-reader"
DENIED = "fixture-other-reader"
AUDITOR = "fixture-data-auditor"
PURPOSE_POLICY = "fixture-data-purpose-policy"
RBAC = "rbac.authorization.k8s.io/v1"
DATASET = "fixture-training-approved-v1"
SCOPE = (
    "On local Kind, an unchecked baseline publishes invented identifiers and an unapproved data "
    "version. A governed processor minimizes the approved version and creates only a hold receipt "
    "for the second. Distinct read-only UIDs with different supplemental groups exercise actual file "
    "reads. Kubernetes separately enforces exact ConfigMap and Pod log read permissions. Pod logs "
    "are application data-access evidence, not API-server or provider-level auditing. A pinned "
    "purpose policy also binds one synthetic source and minimized derivative to one fixture purpose."
)


def create(lab, kind, name, api="v1", **fields):
    return lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields})


def grant(lab, name, resources, account):
    create(lab, "Role", name, RBAC, rules=resources)
    create(lab, "RoleBinding", name, RBAC,
           roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name},
           subjects=[{"kind": "ServiceAccount", "name": account, "namespace": NS}])


def pod(lab, image, name, account, command, uid, groups, *, read_only=False, root=False):
    security = {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                "readOnlyRootFilesystem": True}
    if root:
        security["capabilities"]["add"] = ["CHOWN"]
    lab.create({
        "apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
        "spec": {"restartPolicy": "Never", "serviceAccountName": account,
                 "automountServiceAccountToken": False,
                 "securityContext": {"runAsUser": uid, "runAsGroup": GROUP if uid == 10001 else 10000,
                                     "supplementalGroups": groups, "runAsNonRoot": not root,
                                     "seccompProfile": {"type": "RuntimeDefault"}},
                 "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": PVC}},
                             {"name": "code", "configMap": {"name": CODE}},
                             {"name": "purpose", "configMap": {"name": PURPOSE_POLICY,
                                                                   "defaultMode": 0o444}}],
                 "containers": [{
                     "name": "fixture", "image": image, "imagePullPolicy": "Never", "command": command,
                     "volumeMounts": [{"name": "data", "mountPath": "/store", "readOnly": read_only},
                                      {"name": "code", "mountPath": "/fixture", "readOnly": True},
                                      {"name": "purpose", "mountPath": "/purpose", "readOnly": True}],
                     "securityContext": security,
                     "env": [{"name": env, "valueFrom": {"fieldRef": {"fieldPath": field}}}
                             for env, field in (("POD_NAMESPACE", "metadata.namespace"),
                                                ("POD_ACCOUNT", "spec.serviceAccountName"))],
                 }]}})
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{name}",
                "--timeout=75s", timeout=85)


def principal(account):
    return f"system:serviceaccount:{NS}:{account}"


def observed(lab, name, account=None):
    if account is None:
        return json.loads(lab.kubectl("logs", f"pod/{name}").stdout)
    line = lab.kubectl("logs", f"pod/{name}", "--timestamps", f"--as={principal(account)}").stdout.strip()
    timestamp, event = line.split(" ", 1)
    valid = re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d{1,9})?Z",
                         timestamp)
    if valid:
        datetime.fromisoformat(valid[1])
    return json.loads(event), bool(valid)


def run(lab):
    path = HERE.parent / "SAF-K8S-0908-001" / "case.py"
    spec = importlib.util.spec_from_file_location("saf_0907_002_runtime", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    image = runtime.load_runtime(lab)

    for account in (PROCESSOR, ALLOWED, DENIED, AUDITOR):
        create(lab, "ServiceAccount", account, automountServiceAccountToken=False)
    create(lab, "ConfigMap", CODE, immutable=True, data={
        name: (HERE / name).read_text() for name in ("privacy_worker.py", "data_fixture.py")
    })
    create(lab, "ConfigMap", PURPOSE_POLICY, immutable=True,
           data={"policy.json": (HERE / "purpose-policy.json").read_text()})
    for index, classification in ((INDEX, "internal-synthetic"), (OTHER, "restricted-synthetic")):
        create(lab, "ConfigMap", index, immutable=True, data={"classification": classification})
    create(lab, "PersistentVolumeClaim", PVC, spec={
        "accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "64Mi"}}
    })

    seed = ["sh", "-ec", "mkdir /store/approved /store/held /store/baseline /store/purpose; "
            "chmod 2750 /store/approved /store/purpose; chmod 2700 /store/held /store/baseline; "
            "chown 10001:20100 /store/approved /store/held /store/baseline /store/purpose"]
    pod(lab, image, "fixture-data-seed", PROCESSOR, seed, 0, [], root=True)
    worker = ["python", "/fixture/privacy_worker.py"]
    pod(lab, image, "fixture-unchecked-data", PROCESSOR, [*worker, "baseline"], 10001, [GROUP])
    pod(lab, image, "fixture-governed-data", PROCESSOR, [*worker, "process"], 10001, [GROUP])
    pod(lab, image, "fixture-audit-data", PROCESSOR, [*worker, "inspect"],
        10001, [GROUP], read_only=True)
    inspection = observed(lab, "fixture-audit-data")
    processor = observed(lab, "fixture-governed-data")
    red = {
        "direct_identifiers_reached_unchecked_storage": inspection["unrestricted_baseline_retained_direct_identifiers"],
        "unapproved_version_reached_unchecked_storage": inspection["unrestricted_baseline_published_held_version"],
    }
    lab.check("red", "Unchecked intake publishes identifiers and an unapproved version",
              all(red.values()), red)

    grant(lab, "fixture-data-index-grant", [{
        "apiGroups": [""], "resources": ["configmaps"], "resourceNames": [INDEX], "verbs": ["get"]
    }], ALLOWED)
    read_pods = ["fixture-approved-data-read", "fixture-denied-data-read"]
    grant(lab, "fixture-data-audit-grant", [{
        "apiGroups": [""], "resources": ["pods", "pods/log"], "resourceNames": read_pods, "verbs": ["get"]
    }], AUDITOR)
    for name, account, uid, groups in ((read_pods[0], ALLOWED, 10002, [GROUP]),
                                       (read_pods[1], DENIED, 10003, [])):
        pod(lab, image, name, account, [*worker, "read"], uid, groups, read_only=True)
    allowed_event, allowed_timestamp = observed(lab, read_pods[0], AUDITOR)
    denied_event, denied_timestamp = observed(lab, read_pods[1], AUDITOR)

    api = {}
    for key, resource, account in (("named_index", INDEX, ALLOWED),
                                    ("other_index", OTHER, ALLOWED), ("wrong_reader", INDEX, DENIED)):
        result = lab.kubectl("get", "configmap", resource, "-o", "json",
                             f"--as={principal(account)}", allow_failure=True)
        if result.returncode == 0:
            api[key] = json.loads(result.stdout)["data"]["classification"]
        else:
            api[key] = "forbidden" if "Forbidden" in result.stderr else "unexpected-error"
    audit_denial = lab.kubectl("logs", f"pod/{read_pods[0]}", f"--as={principal(DENIED)}",
                               allow_failure=True)
    green = {
        "held_file_absent": inspection["held_dataset_has_disposition_only"],
        "invented_direct_identifier_fields_and_values_removed":
            inspection["approved_durable_output_matches_minimized_contract"],
        "unapproved_uid_denied_at_file_boundary": denied_event == {
            "event": "training-data-read", "dataset_id": DATASET, "principal": principal(DENIED),
            "uid": 10003, "decision": "denied", "reason": "permission-denied",
        },
        "named_kubernetes_api_scope_enforced": api == {
            "named_index": "internal-synthetic", "other_index": "forbidden", "wrong_reader": "forbidden",
        },
        "unapproved_reader_cannot_read_someone_elses_audit_log":
            audit_denial.returncode != 0 and "Forbidden" in audit_denial.stderr,
    }
    lab.check("green", "Governed intake holds unapproved data and denies out-of-scope reads",
              all(green.values()), green)
    positive = {
        "approved_uid_reads_exact_minimized_bytes": allowed_event == {
            "event": "training-data-read", "dataset_id": DATASET, "principal": principal(ALLOWED),
            "uid": 10002, "decision": "allowed", "output_sha256": inspection["approved_sha256"], "row_count": 2,
        } and inspection["approved_sha256"] == processor["approved"]["output_sha256"],
        "scoped_auditor_queries_both_timestamped_events": allowed_timestamp and denied_timestamp,
    }
    lab.check("positive", "Authorized reader and scoped auditor can use the minimized data path",
              all(positive.values()), positive)

    pod(lab, image, "fixture-purpose-transform", PROCESSOR,
        [*worker, "purpose"], 10001, [GROUP])
    purpose_result = observed(lab, "fixture-purpose-transform")
    pod(lab, image, "fixture-purpose-outsider", DENIED,
        [*worker, "purpose-outsider"], 10003, [], read_only=True)
    outsider_result = observed(lab, "fixture-purpose-outsider")
    pod(lab, image, "fixture-purpose-audit", AUDITOR,
        [*worker, "inspect-purpose"], 10002, [GROUP], read_only=True)
    derivative = observed(lab, "fixture-purpose-audit")

    grant(lab, "fixture-purpose-policy-reader", [{
        "apiGroups": [""], "resources": ["configmaps"], "resourceNames": [PURPOSE_POLICY],
        "verbs": ["get"]
    }], PROCESSOR)
    processor_subject = principal(PROCESSOR)
    policy_patch_can = lab.kubectl("auth", "can-i", "patch", f"configmaps/{PURPOSE_POLICY}",
                                   f"--as={processor_subject}", allow_failure=True)
    policy_before = json.loads(lab.kubectl("get", "configmap", PURPOSE_POLICY, "-o", "json").stdout)
    scoped_read = lab.kubectl("get", "configmap", PURPOSE_POLICY, "-o", "json",
                              f"--as={processor_subject}", allow_failure=True)
    patch_result = lab.kubectl("patch", "configmap", PURPOSE_POLICY, "--type=merge", "-p",
                               json.dumps({"metadata": {"annotations": {"saf-test/probe": "inert"}}}),
                               f"--as={processor_subject}", allow_failure=True)
    policy_after = json.loads(lab.kubectl("get", "configmap", PURPOSE_POLICY, "-o", "json").stdout)
    policy_auth = {
        "purpose_policy_is_immutable": policy_before.get("immutable") is True,
        "processor_can_read_purpose_policy": scoped_read.returncode == 0
        and json.loads(scoped_read.stdout)["data"] == policy_before["data"],
        "processor_cannot_patch_purpose_policy": policy_patch_can.returncode == 1
        and policy_patch_can.stdout.strip() == "no",
        "actual_policy_patch_is_forbidden": patch_result.returncode != 0
        and "forbidden" in patch_result.stderr.lower()
        and "cannot patch resource" in patch_result.stderr.lower(),
        "policy_digest_unchanged": hashlib.sha256(policy_before["data"]["policy.json"].encode()).hexdigest()
        == hashlib.sha256(policy_after["data"]["policy.json"].encode()).hexdigest(),
        "policy_object_unchanged": policy_before == policy_after,
    }
    purpose_check = {
        "actual_processor_identity_is_scoped": purpose_result["principal_account"] == PROCESSOR
        and purpose_result["principal_name"] == processor_subject,
        "policy_digest_matches_independent_code_pin": purpose_result["policy_digest_matches_pin"],
        "exact_source_purpose_and_derivative_are_approved":
            purpose_result["approved_request"]["accepted"] is True
            and purpose_result["approved_request"]["reason"] == "approved"
            and purpose_result["approved_request"]["derivative_created"] is True
            and purpose_result["approved_request"]["derivative_digest_matches_policy"] is True,
        "wrong_purpose_version_parent_digest_are_held_without_outputs":
            purpose_result["denied_requests"] == {
                "wrong-purpose": {"accepted": False, "reason": "purpose_not_approved", "denied_output_absent": True},
                "wrong-version": {"accepted": False, "reason": "source_scope_or_digest_mismatch",
                                  "denied_output_absent": True},
                "wrong-parent-digest": {"accepted": False, "reason": "parent_digest_not_approved",
                                        "denied_output_absent": True},
            } and purpose_result["denied_outputs_absent"],
        "other_actual_service_account_cannot_authorize_derivative":
            outsider_result["principal_account"] == DENIED and outsider_result["request_denied"]
            and outsider_result["reason"] == "principal_not_approved"
            and outsider_result["derivative_write_not_attempted"],
        "independent_reader_verifies_exact_derivative_scope_and_bytes":
            all(derivative[key] is True for key in (
                "derivative_present", "source_id_bound", "source_digest_bound",
                "target_id_version_purpose_bound", "target_approval_and_classification_bound",
                "approved_minimized_data_exact", "derivative_digest_exact",
                "identifier_fields_and_values_absent"))
            and derivative["row_count"] == 2,
        "derivative_is_unchanged_after_denied_identity_request":
            purpose_result["approved_request"]["derivative_sha256"]
            == derivative["derivative_sha256"] == "dacc51e337faa9002ff532eba8b9504ecaefadf3bac25bcd0d86a92f5a2f3b61",
    }
    lab.check("positive", "Purpose and immutable source scope gate an exact minimized derivative before independent readback",
              all(policy_auth.values()) and all(purpose_check.values()),
              {"policy_authority": policy_auth, "purpose_bound_derivative": purpose_check,
               "derivative_file_sha256": derivative["file_sha256"]})
    (lab.evidence / "privacy-classification-observations.json").write_text(json.dumps({
        "processor": processor, "durable_observation": inspection, "api_reads": api,
        "access_events": [allowed_event, denied_event],
        "timestamped_log_records_verified": [allowed_timestamp, denied_timestamp],
        "purpose_result": purpose_result, "purpose_outsider": outsider_result,
        "purpose_derivative": derivative, "purpose_policy_authority": policy_auth,
        "checks": {"red": red, "green": green, "positive": positive},
    }, indent=2, sort_keys=True) + "\n")
