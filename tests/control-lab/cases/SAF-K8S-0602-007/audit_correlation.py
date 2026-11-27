"""Correlate the inert approval updates with this Kind API server's local audit log."""
import json
from pathlib import Path
import time


NS = "saf-test"
RECORD = "saf-0602-007-review"
AUDIT_DIR = "/var/log/kubernetes/saf-0602-007-audit"
AUDIT_LOG = f"{AUDIT_DIR}/audit.log"
MAX_AUDIT_BYTES = 2 * 1024 * 1024
MAX_AUDIT_EVENTS = 512

SECURITY = f"system:serviceaccount:{NS}:saf-security"
OPERATIONS = f"system:serviceaccount:{NS}:saf-operations"
REQUESTER = f"system:serviceaccount:{NS}:saf-requester"
POLICY = "saf-0602-007-record-integrity"
POLICY_MESSAGE = "only the designated reviewer can approve its own field on this exact record"

APPROVED = {
    "requestId": "saf-0602-007-synthetic-request",
    "targetDigest": "sha256:" + "a" * 64,
    "expiresAt": "2032-01-01T00:15:00Z",
    "security": "approved",
    "operations": "approved",
}


def prepare_kind(lab, temporary):
    """Enable RequestResponse audit only for ConfigMap patch/update in saf-test."""
    temporary = Path(temporary)
    audit_dir = temporary / "saf-0602-007-audit"
    audit_dir.mkdir(mode=0o700)
    policy = temporary / "saf-0602-007-audit-policy.yaml"
    policy.write_text(
        "apiVersion: audit.k8s.io/v1\n"
        "kind: Policy\n"
        "omitStages: [RequestReceived]\n"
        "rules:\n"
        "  - level: RequestResponse\n"
        f"    namespaces: [{NS}]\n"
        "    verbs: [patch, update]\n"
        '    resources: [{group: "", resources: [configmaps]}]\n'
        "  - level: None\n",
        encoding="utf-8",
    )
    lab.approval_audit_file = audit_dir / "audit.log"
    config = temporary / "kind-saf-0602-007-audit.yaml"
    config.write_text(f'''kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: {json.dumps(str(policy))}
        containerPath: /etc/kubernetes/saf-0602-007-audit-policy.yaml
        readOnly: true
      - hostPath: {json.dumps(str(audit_dir))}
        containerPath: {AUDIT_DIR}
        readOnly: false
kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta4
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        - name: audit-policy-file
          value: /etc/kubernetes/saf-0602-007-audit-policy.yaml
        - name: audit-log-path
          value: {AUDIT_LOG}
        - name: audit-log-mode
          value: blocking
      extraVolumes:
        - name: saf-0602-007-audit-policy
          hostPath: /etc/kubernetes/saf-0602-007-audit-policy.yaml
          mountPath: /etc/kubernetes/saf-0602-007-audit-policy.yaml
          readOnly: true
          pathType: File
        - name: saf-0602-007-audit-log
          hostPath: {AUDIT_DIR}
          mountPath: {AUDIT_DIR}
          readOnly: false
          pathType: DirectoryOrCreate
''', encoding="utf-8")
    return config


def _request_data(event):
    request = event.get("requestObject")
    if isinstance(request, dict) and isinstance(request.get("data"), dict):
        return request["data"]
    return {}


def _response_data(event):
    response = event.get("responseObject")
    if isinstance(response, dict) and isinstance(response.get("data"), dict):
        return response["data"]
    return {}


def _event_matches_fixture(event):
    ref = event.get("objectRef") or {}
    return (ref.get("resource") == "configmaps"
            and ref.get("namespace") == NS
            and ref.get("name") == RECORD
            and event.get("verb") in {"patch", "update"})


def _project_event(event):
    """Retain only allowlisted fixed fixture values; omit origin-user extras."""
    request_data = _request_data(event)
    response_data = _response_data(event)
    fields = ("requestId", "targetDigest", "expiresAt", "security", "operations")
    status = event.get("responseStatus") or {}
    impersonated = (event.get("impersonatedUser") or {}).get("username")
    message = status.get("message", "")
    return {
        "audit_id": event.get("auditID"),
        "stage": event.get("stage"),
        "stage_timestamp": event.get("stageTimestamp"),
        "level": event.get("level"),
        "verb": event.get("verb"),
        "namespace": (event.get("objectRef") or {}).get("namespace"),
        "name": (event.get("objectRef") or {}).get("name"),
        "impersonated_identity": impersonated,
        "status_code": status.get("code"),
        "authorization_denied": (event.get("annotations") or {}).get(
            "authorization.k8s.io/decision") == "forbid",
        "policy_denial_observed": POLICY in message and POLICY_MESSAGE in message,
        "request_data": {key: request_data[key] for key in fields if key in request_data},
        "response_data": {key: response_data[key] for key in fields if key in response_data},
    }


def _successful_vote(events, actor, field, expected_response):
    matches = [event for event in events
               if event["impersonated_identity"] == actor
               and event["status_code"] == 200
               and event["request_data"].get(field) == "approved"
               and event["response_data"] == expected_response]
    return matches


def run(lab):
    audit_file = getattr(lab, "approval_audit_file", None)
    if audit_file is None or not Path(audit_file).is_file():
        lab.block("The case-owned Kubernetes audit file was not created")
    audit_file = Path(audit_file)
    if audit_file.stat().st_size > MAX_AUDIT_BYTES:
        lab.block("The scoped case audit log exceeded its fixed size bound")
    lines = audit_file.read_text(encoding="utf-8").splitlines()
    if len(lines) > MAX_AUDIT_EVENTS:
        lab.block("The scoped case audit log exceeded its fixed event bound")

    candidates = []
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            lab.block("The bounded Kubernetes audit file contained an incomplete JSON event")
        if _event_matches_fixture(event):
            candidates.append(event)

    # The denial may be emitted during the existing admission-policy readiness
    # loop. Blocking audit mode makes completed API requests available before the
    # final API read; this short bounded retry handles only file-flush visibility.
    deadline = time.monotonic() + 3
    while not candidates and time.monotonic() < deadline:
        time.sleep(0.1)
        if audit_file.stat().st_size > MAX_AUDIT_BYTES:
            lab.block("The scoped case audit log exceeded its fixed size bound")
        lines = audit_file.read_text(encoding="utf-8").splitlines()
        if len(lines) > MAX_AUDIT_EVENTS:
            lab.block("The scoped case audit log exceeded its fixed event bound")
        candidates = []
        for line in lines:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                lab.block("The bounded Kubernetes audit file contained an incomplete JSON event")
            if _event_matches_fixture(event):
                candidates.append(event)

    projected = [_project_event(event) for event in candidates]
    completed = [event for event in projected
                 if event["stage"] == "ResponseComplete"
                 and event["level"] == "RequestResponse"
                 and event["audit_id"]]
    denied_cross_vote = any(
        event["impersonated_identity"] == SECURITY
        and event["verb"] == "patch"
        and event["status_code"] == 403
        and event["policy_denial_observed"]
        and event["request_data"].get("operations") == "approved"
        for event in completed)
    requester_denial = any(
        event["impersonated_identity"] == REQUESTER
        and event["verb"] == "patch"
        and event["status_code"] == 403
        and event["authorization_denied"]
        for event in completed)
    security_expected = {**APPROVED, "operations": "pending"}
    security_approval = _successful_vote(completed, SECURITY, "security", security_expected)
    operations_approval = _successful_vote(completed, OPERATIONS, "operations", APPROVED)
    distinct_events = (bool(security_approval) and bool(operations_approval)
                       and len({security_approval[0]["audit_id"],
                                operations_approval[0]["audit_id"]}) == 2)

    final = json.loads(lab.kubectl(
        "-n", NS, "get", "configmap", RECORD, "-o", "json").stdout)
    final_matches = final.get("data") == APPROVED
    exact_actor_set = ({event["impersonated_identity"] for event in completed
                        if (event["status_code"] == 200
                            and (event["request_data"].get("security") == "approved"
                                 or event["request_data"].get("operations") == "approved"))}
                       == {SECURITY, OPERATIONS})
    passed = (denied_cross_vote and bool(security_approval) and bool(operations_approval)
              and requester_denial and distinct_events and final_matches and exact_actor_set)

    raw = {
        "scope": "Host-local Kubernetes audit logging for patch/update ConfigMap requests in the sole fixture namespace; selected events correlate the inert approved request by object name, synthetic impersonated identity, approval fields, audit ID and API status.",
        "policy_scope": {"namespace": NS, "verbs": ["patch", "update"],
                         "resource": "core/configmaps", "level": "RequestResponse",
                         "log_mode": "blocking", "maximum_log_bytes": MAX_AUDIT_BYTES,
                         "maximum_event_lines": MAX_AUDIT_EVENTS},
        "record": {"namespace": NS, "name": RECORD,
                   "request_id": APPROVED["requestId"],
                   "target_digest": APPROVED["targetDigest"],
                   "expires_at": APPROVED["expiresAt"],
                   "final_data_matches_expected": final_matches},
        "exact_synthetic_identities": {"security": SECURITY,
                                       "operations": OPERATIONS,
                                       "requester": REQUESTER},
        "impersonation_based_identity": True,
        "denied_cross_vote_has_correlated_policy_event": denied_cross_vote,
        "requester_patch_denial_has_correlated_identity_event": requester_denial,
        "security_approval_has_correlated_success_event": bool(security_approval),
        "operations_approval_has_correlated_success_event": bool(operations_approval),
        "approval_event_ids_distinct": distinct_events,
        "event_request_identity_set_exact": exact_actor_set,
        "captured_event_count": len(completed),
        "selected_events": completed,
        "remote_delivery_or_retention_claimed": False,
        "human_identity_or_signature_bypass_claimed": False,
    }
    (lab.evidence / "approval-audit-correlation.raw.json").write_text(
        json.dumps(raw, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    lab.check(
        "positive",
        "Local Kubernetes audit events correlate the denied cross-vote and two approved synthetic reviewers to the exact inert request",
        passed,
        {"scoped_policy_and_response_events_present": bool(completed),
         "cross_vote_denial_correlated_by_identity_request_and_policy": denied_cross_vote,
         "requester_write_denial_correlated_by_exact_identity": requester_denial,
         "separate_exact_reviewer_success_events": bool(security_approval) and bool(operations_approval),
         "approved_record_readback_matches_fixed_request": final_matches,
         "raw_evidence": "approval-audit-correlation.raw.json"})
