"""Exercise a synthetic audit-response decision through live Kubernetes RBAC."""
import hashlib
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-1001-008"
RESPONDER = "system:serviceaccount:saf-1001-008:response-investigator"
PEER = "system:serviceaccount:saf-1001-008:reviewer-peer"
TARGET = "finding-approved"
BASELINE = "finding-peer-baseline"
NEIGHBOR = "finding-unapproved-neighbor"
ROLE = "approved-finding-read"
BINDING = "approved-finding-read"
GROUPS = ["system:serviceaccounts", f"system:serviceaccounts:{NAMESPACE}", "system:authenticated"]
EXPECTED_RULE = [{
    "apiGroups": [""], "resources": ["configmaps"], "resourceNames": [TARGET], "verbs": ["get"]
}]

SCOPE = (
    "A disposable Kind Kubernetes v1.36.1 cluster with four inert ConfigMaps and two "
    "synthetic ServiceAccount identities. The case checks a matrix-backed, read-only "
    "investigation decision through an actual impersonated ConfigMap GET, API-server "
    "SubjectAccessReview, and live Role/RoleBinding readback. It does not create Pods, "
    "tokens, or persistent workloads. Approval identities and all finding data are "
    "synthetic. The case does not establish organizational approval, real audit event "
    "handling, ticketing/workflow automation, escalation delivery, policy changes, "
    "production authorization, or organizational closure verification."
)


def kubectl(lab, *args, **kwargs):
    return lab.kubectl("-n", NAMESPACE, *args, **kwargs)


def create_configmap(lab, name, data):
    obj = {"apiVersion": "v1", "kind": "ConfigMap",
           "metadata": {"name": name, "namespace": NAMESPACE,
                        "labels": {"saf-k8s.example/fixture": "true"}},
           "data": data, "immutable": True}
    kubectl(lab, "create", "-f", "-", payload=json.dumps(obj))


def review(lab, username, name):
    request = {
        "apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview",
        "spec": {"user": username, "groups": GROUPS,
                 "resourceAttributes": {"namespace": NAMESPACE, "verb": "get",
                                        "group": "", "resource": "configmaps", "name": name}},
    }
    result = lab.kubectl("create", "-f", "-", "-o", "json", payload=json.dumps(request))
    status = json.loads(result.stdout).get("status", {})
    if status.get("evaluationError"):
        raise RuntimeError(f"SubjectAccessReview returned an evaluation error: {status['evaluationError']}")
    return {"allowed": status.get("allowed", False),
            "denied": status.get("denied", False), "reason": status.get("reason", "")}


def get_as(lab, username, name):
    args = ["get", "configmap", name, "-o", "json", "--as", username]
    for group in GROUPS:
        args.extend(["--as-group", group])
    return kubectl(lab, *args, allow_failure=True)


def allowed_get(lab, username, name):
    deadline = time.monotonic() + 10
    while True:
        result = get_as(lab, username, name)
        if result.returncode == 0 or time.monotonic() >= deadline:
            return result
        if not forbidden(result):
            lab.block(f"Unexpected authorization response for fixture {name}")
        time.sleep(0.25)


def forbidden(result):
    return result.returncode != 0 and "forbidden" in result.stderr.lower()


def readback(lab):
    role = json.loads(kubectl(lab, "get", "role", ROLE, "-o", "json").stdout)
    binding = json.loads(kubectl(lab, "get", "rolebinding", BINDING, "-o", "json").stdout)
    return {
        "role_rules_match": role.get("rules") == EXPECTED_RULE,
        "role_namespace": role.get("metadata", {}).get("namespace"),
        "role_namespace_matches": role.get("metadata", {}).get("namespace") == NAMESPACE,
        "binding_role_ref": binding.get("roleRef"),
        "binding_subjects": binding.get("subjects"),
        "binding_matches": (
            binding.get("metadata", {}).get("namespace") == NAMESPACE
            and binding.get("roleRef") == {
                "apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": ROLE
            }
            and binding.get("subjects") == [{
                "kind": "ServiceAccount", "name": "response-investigator", "namespace": NAMESPACE
            }]
        ),
    }


def make_role(lab):
    role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": ROLE, "namespace": NAMESPACE}, "rules": EXPECTED_RULE}
    kubectl(lab, "create", "-f", "-", payload=json.dumps(role))


def validate_decision(matrix, decision, matrix_digest):
    actions = {item.get("action"): item for item in matrix.get("actions", [])}
    required_actions = ["investigation_read", "access_control_modification"]
    approvals_cover_actions = all(
        actions.get(name, {}).get("permitted") is True
        and actions.get(name, {}).get("decision") == "approved"
        and actions.get(name, {}).get("approval_id") == decision.get("approval_id")
        and set(actions.get(name, {}).get("required_approvers", []))
        <= set(decision.get("approver_identities", []))
        for name in required_actions
    )
    if (decision.get("status") != "approved" or decision.get("namespace") != NAMESPACE
            or decision.get("subject") != RESPONDER
            or decision.get("resource") != f"configmaps/{TARGET}"
            or decision.get("verbs") != ["get"]
            or decision.get("authorization_actions") != required_actions
            or not approvals_cover_actions
            or decision.get("approval_id") != "SYN-APPROVAL-008-01"
            or decision.get("approver_identities") != ["synthetic-grc-approver", "synthetic-audit-owner", "synthetic-iam-approver", "synthetic-resource-owner"]
            or decision.get("expires") != "case-run-only"
            or decision.get("matrix_sha256") != matrix_digest):
        raise ValueError("Synthetic approval decision does not match this exact read-only fixture grant")


def apply_approved_binding(lab):
    binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": BINDING, "namespace": NAMESPACE},
        "subjects": [{"kind": "ServiceAccount", "name": "response-investigator", "namespace": NAMESPACE}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": ROLE},
    }
    kubectl(lab, "create", "-f", "-", payload=json.dumps(binding))


def run(lab):
    matrix_raw = (HERE / "authorization-matrix.json").read_text()
    matrix = json.loads(matrix_raw)
    digest = hashlib.sha256(matrix_raw.encode()).hexdigest()
    decision = matrix["enforcement_decision"]
    if matrix.get("fixture_type") != "synthetic-audit-response-authorization-matrix":
        raise ValueError("Unexpected fixture type")

    lab.kubectl("create", "namespace", NAMESPACE)
    server = json.loads(lab.kubectl("version", "-o", "json").stdout).get("serverVersion", {})
    lab.check("positive", "The case is running against the requested Kubernetes v1.36.1 API server",
              server.get("gitVersion") == "v1.36.1", server)
    for name in ("response-investigator", "reviewer-peer"):
        kubectl(lab, "create", "serviceaccount", name)
    create_configmap(lab, TARGET, {"finding.json": json.dumps(matrix["finding"], sort_keys=True)})
    create_configmap(lab, BASELINE, {"finding.json": json.dumps({
        "id": "SYN-AUDIT-008-PEER", "source": "mock metadata", "summary": "Harmless reviewer peer fixture."
    }, sort_keys=True)})
    create_configmap(lab, NEIGHBOR, {"finding.json": json.dumps({
        "id": "SYN-AUDIT-008-02", "source": "mock metadata", "summary": "Unapproved neighboring fixture."
    }, sort_keys=True)})

    make_role(lab)
    peer_role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                 "metadata": {"name": "peer-finding-read", "namespace": NAMESPACE},
                 "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                            "resourceNames": [BASELINE], "verbs": ["get"]}]}
    kubectl(lab, "create", "-f", "-", payload=json.dumps(peer_role))
    peer_binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": "peer-finding-read", "namespace": NAMESPACE},
        "subjects": [{"kind": "ServiceAccount", "name": "reviewer-peer", "namespace": NAMESPACE}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "peer-finding-read"},
    }
    kubectl(lab, "create", "-f", "-", payload=json.dumps(peer_binding))

    before = get_as(lab, RESPONDER, TARGET)
    before_sar = review(lab, RESPONDER, TARGET)
    peer_before = allowed_get(lab, PEER, BASELINE)
    peer_before_sar = review(lab, PEER, BASELINE)
    neighbor_before = get_as(lab, RESPONDER, NEIGHBOR)
    lab.check("red", "The unbound responder cannot read the approved finding before the grant is enforced",
              forbidden(before) and forbidden(neighbor_before) and not before_sar["allowed"],
              {"actual_get_denied": before.returncode != 0, "sar": before_sar,
               "unapproved_neighbor_denied": neighbor_before.returncode != 0})
    lab.check("positive", "An independently authorized peer can read only its harmless named fixture",
              peer_before.returncode == 0 and peer_before_sar["allowed"]
              and json.loads(peer_before.stdout).get("data", {}).get("finding.json") is not None,
              {"actual_get_allowed": peer_before.returncode == 0, "sar": peer_before_sar})

    approval_data = {"matrix.json": matrix_raw,
                     "matrix_sha256": digest,
                     "fixture_notice": "Synthetic approval only; no organizational approval is represented."}
    create_configmap(lab, "approved-response-decision", approval_data)
    observed_approval = json.loads(kubectl(lab, "get", "configmap", "approved-response-decision", "-o", "json").stdout)
    observed_matrix_raw = observed_approval.get("data", {}).get("matrix.json", "{}")
    observed_matrix = json.loads(observed_matrix_raw)
    if hashlib.sha256(observed_matrix_raw.encode()).hexdigest() != digest:
        raise ValueError("Live synthetic approval ConfigMap does not match the reviewed matrix fixture")
    decision = dict(observed_matrix.get("enforcement_decision", {}))
    decision["matrix_sha256"] = observed_approval.get("data", {}).get("matrix_sha256")
    unapproved = {**decision, "approver_identities": decision["approver_identities"][:-1]}
    try:
        validate_decision(observed_matrix, unapproved, digest)
    except ValueError:
        unapproved_rejected = True
    else:
        unapproved_rejected = False
    no_binding = kubectl(lab, "get", "rolebinding", BINDING, "--ignore-not-found", "-o", "name")
    lab.check("red", "A synthetic decision missing a required approver cannot authorize the binding",
              unapproved_rejected and not no_binding.stdout.strip(),
              {"missing_approver_rejected": unapproved_rejected,
               "responder_binding_absent": not no_binding.stdout.strip()})
    validate_decision(observed_matrix, decision, digest)
    apply_approved_binding(lab)
    after = allowed_get(lab, RESPONDER, TARGET)
    after_sar = review(lab, RESPONDER, TARGET)
    neighbor_after = get_as(lab, RESPONDER, NEIGHBOR)
    baseline_after = get_as(lab, RESPONDER, BASELINE)
    peer_after = get_as(lab, PEER, BASELINE)
    rb_readback = readback(lab)
    target_read = json.loads(after.stdout) if after.returncode == 0 else {}
    target_exact = target_read.get("metadata", {}).get("name") == TARGET
    lab.check("green", "The approved decision enables the exact harmless read and live RBAC matches its scope",
              after.returncode == 0 and target_exact and after_sar["allowed"]
              and not after_sar["denied"] and forbidden(neighbor_after)
              and forbidden(baseline_after) and peer_after.returncode == 0
              and rb_readback["role_rules_match"] and rb_readback["role_namespace_matches"]
              and rb_readback["binding_matches"],
              {"actual_target_get_allowed": after.returncode == 0, "target_exact": target_exact,
               "sar": after_sar, "neighbor_denied": neighbor_after.returncode != 0,
               "unapproved_baseline_denied": baseline_after.returncode != 0,
               "positive_peer_still_allowed": peer_after.returncode == 0,
               "rbac_readback": rb_readback})

    evidence = {
        "control_id": "SAF-K8S-1001-008", "namespace": NAMESPACE,
        "evidence_notice": "Synthetic fixture data and identities only; no credentials or secrets are recorded.",
        "authorization_matrix_sha256": digest,
        "approval_id": decision["approval_id"], "synthetic_approval_status": decision["status"],
        "approval_configmap_sha256": observed_approval.get("data", {}).get("matrix_sha256"),
        "responder": RESPONDER, "peer": PEER,
        "before_enforcement": {
            "responder_target_get": {"exit_code": before.returncode,
                                     "stdout": before.stdout, "stderr": before.stderr},
            "responder_target_sar": before_sar,
            "responder_neighbor_denied": neighbor_before.returncode != 0,
            "peer_baseline_get": {"exit_code": peer_before.returncode,
                                  "object": json.loads(peer_before.stdout) if peer_before.returncode == 0 else None},
            "peer_baseline_sar": peer_before_sar,
        },
        "after_enforcement": {
            "responder_target_get": {"exit_code": after.returncode, "object": target_read},
            "responder_target_sar": after_sar,
            "responder_neighbor_denied": neighbor_after.returncode != 0,
            "responder_baseline_denied": baseline_after.returncode != 0,
            "peer_baseline_get_exit_code": peer_after.returncode,
            "rbac_readback": rb_readback,
        },
        "coverage_limits": [
            "The approval matrix and approver identities are synthetic fixtures, not organizational evidence.",
            "Escalation routing, policy changes, ticketing, production controls, real audit sources, and closure workflows are not exercised.",
            "The observed enforcement is one namespace-scoped ConfigMap GET decision in a disposable Kind cluster."
        ],
    }
    (lab.evidence / "raw-response-evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
