"""Scoped audit-profile draft for SAF-K8S-0304-004.

This is an additive profile for the supplied passing case. It is not a
standalone runner and must only be bootstrapped into that case's disposable
Kind cluster. Existing case checks and their comparator remain unchanged.
"""

import json
from urllib.parse import urlsplit


NAMESPACE = "saf-test"
POD = "ephemeral-target"
APPROVED = "system:serviceaccount:saf-test:debugger"
UNAPPROVED = "system:serviceaccount:saf-test:unapproved"
AUDIT_DIR_IN_NODE = "/var/log/kubernetes/audit"
AUDIT_FILE_IN_NODE = AUDIT_DIR_IN_NODE + "/audit.log"
TARGET_URI = f"/api/v1/namespaces/{NAMESPACE}/pods/{POD}/ephemeralcontainers"


def audit_policy_text():
    """Only metadata for this fixture namespace and exact subresource."""
    return (
        "apiVersion: audit.k8s.io/v1\n"
        "kind: Policy\n"
        "omitStages: [RequestReceived, ResponseStarted, Panic]\n"
        "rules:\n"
        "  - level: Metadata\n"
        "    verbs: [update, patch]\n"
        f"    namespaces: [{NAMESPACE}]\n"
        "    resources:\n"
        "      - group: \"\"\n"
        "        resources: [pods/ephemeralcontainers]\n"
        "  - level: None\n"
    )


def kind_config_text(policy_host_path, audit_host_dir):
    """Pattern for the runner's pre-create Kind config hook.

    Both host paths must be children of the runner-owned temporary directory.
    The policy is mounted read-only; only the temporary audit directory is
    writable by the control-plane node.
    """
    return (
        "kind: Cluster\n"
        "apiVersion: kind.x-k8s.io/v1alpha4\n"
        "nodes:\n"
        "  - role: control-plane\n"
        "    extraMounts:\n"
        f"      - hostPath: {json.dumps(str(policy_host_path))}\n"
        "        containerPath: /etc/kubernetes/audit-policy.yaml\n"
        "        readOnly: true\n"
        f"      - hostPath: {json.dumps(str(audit_host_dir))}\n"
        f"        containerPath: {AUDIT_DIR_IN_NODE}\n"
        "        readOnly: false\n"
        "kubeadmConfigPatches:\n"
        "  - |\n"
        "    apiVersion: kubeadm.k8s.io/v1beta4\n"
        "    kind: ClusterConfiguration\n"
        "    apiServer:\n"
        "      extraArgs:\n"
        "        - name: audit-policy-file\n"
        "          value: /etc/kubernetes/audit-policy.yaml\n"
        f"        - name: audit-log-path\n          value: {AUDIT_FILE_IN_NODE}\n"
        "        - name: audit-log-format\n          value: json\n"
        "        - name: audit-log-mode\n          value: blocking\n"
        "        - name: audit-log-maxsize\n          value: \"10\"\n"
        "        - name: audit-log-maxbackup\n          value: \"2\"\n"
        "        - name: audit-log-maxage\n          value: \"1\"\n"
        "      extraVolumes:\n"
        "        - name: audit-policy\n"
        "          hostPath: /etc/kubernetes/audit-policy.yaml\n"
        "          mountPath: /etc/kubernetes/audit-policy.yaml\n"
        "          readOnly: true\n"
        "          pathType: File\n"
        "        - name: audit-log\n"
        f"          hostPath: {AUDIT_DIR_IN_NODE}\n"
        f"          mountPath: {AUDIT_DIR_IN_NODE}\n"
        "          readOnly: false\n"
        "          pathType: DirectoryOrCreate\n"
    )


def effective_username(event):
    """Resolve kubectl --as identity while retaining a strict username check."""
    impersonated = event.get("impersonatedUser") or {}
    return impersonated.get("username") or event.get("user", {}).get("username")


def matching_events(audit_path, byte_offset):
    """Read newly appended JSONL, retaining only this fixture's exact target."""
    result = []
    with open(audit_path, "rb") as source:
        source.seek(byte_offset)
        for raw_line in source:
            try:
                event = json.loads(raw_line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            uri = urlsplit(event.get("requestURI", ""))
            ref = event.get("objectRef") or {}
            if (
                uri.path == TARGET_URI
                and ref.get("apiGroup", "") == ""
                and ref.get("resource") == "pods"
                and ref.get("subresource") == "ephemeralcontainers"
                and ref.get("namespace") == NAMESPACE
                and ref.get("name") == POD
                and event.get("stage") == "ResponseComplete"
            ):
                result.append(event)
    return result


def assert_fixture_audit_events(events, expected):
    """Compare exact identity/verb/status tuples; do not alter case comparator.

    expected is an ordered list of (identity, verb, status, dry_run), where
    status is the exact HTTP response code expected from the fixture request.
    This checks metadata-only output and at most one ResponseComplete per
    auditID. It deliberately emits no event payload or raw identity metadata.
    """
    observed = []
    seen_audit_ids = set()
    for event in events:
        audit_id = event.get("auditID")
        if not audit_id or audit_id in seen_audit_ids:
            raise AssertionError("missing or duplicate auditID")
        seen_audit_ids.add(audit_id)
        if "requestObject" in event or "responseObject" in event:
            raise AssertionError("audit record contains an object payload")
        query = urlsplit(event.get("requestURI", "")).query
        dry_run = "dryRun=All" in query.split("&")
        status = (event.get("responseStatus") or {}).get("code")
        observed.append((effective_username(event), event.get("verb"), status, dry_run))

    if sorted(observed) != sorted(expected):
        raise AssertionError("fixture audit metadata did not match expected operations")


# Add these expectations only after the corresponding existing requests have
# run. Every denied/noncompliant operation in the supplied case remains a
# server-side dry run. Keep the current assertions/comparator unchanged.
EXPECTED_EXAMPLE = [
    (UNAPPROVED, "update", 403, True),    # existing unauthorized update
    (UNAPPROVED, "patch", 403, True),     # existing unauthorized patch
    (APPROVED, "update", 403, True),      # existing restricted-PSA denial
    (APPROVED, "update", 422, True),      # existing duplicate-name denial
    (APPROVED, "update", 200, False),     # existing permitted marker update
]
