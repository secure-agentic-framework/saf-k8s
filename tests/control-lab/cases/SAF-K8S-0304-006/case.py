"""Verify scoped admission, authorization expiry and a read-only fixture mount."""
import json
from datetime import datetime, timezone
import importlib.machinery
import importlib.util
from pathlib import Path
import time
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).parent
FIXTURES = json.loads((HERE / "fixtures.json").read_text())
NAMESPACE = "saf-0304-hostpath-policy"
EXCEPTION_NAMESPACE = "saf-0304-hostpath-exception"
POLICY_VERSION = "v1.36"
DENIAL_MARKER = "violates PodSecurity"
VAP_DENIAL_MARKER = "SAF hostPath approval does not match this request"
APPROVAL_NAME = "saf-hostpath-approval-collector"
POLICY_NAME = "saf-hostpath-exception-policy"
APPROVED_IDENTITY = (
    f"system:serviceaccount:{EXCEPTION_NAMESPACE}:saf-hostpath-requester"
)
UNAPPROVED_IDENTITY = (
    f"system:serviceaccount:{EXCEPTION_NAMESPACE}:saf-hostpath-unapproved"
)
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
MARKER_PATH = "/var/lib/saf-0304-006-fixture/collector-marker"
MARKER_CONTENT = "saf-0304-006 owned collector marker"
OBSERVED_MANAGER = "saf-0304-006-observe"
SYNC_MANAGER = "saf-0304-006-sync"
SCOPE = (
    "Default hostPath denial using pinned Baseline PSA, plus a scoped allowance for one read-only "
    "case-owned marker on a disposable Kind node. Negative Pod requests are server dry-runs. "
    "The case reconciles its exact approval with a deterministic clock and verifies native Metadata audit."
)

# This clock is intentionally independent of wall time and Kubernetes server time.
# The test accepts the exact request at the first instant, advances this fixture
# clock, reconciles the owned approval away, then proves the same request is denied.
FIXTURE_CLOCK_APPROVED = "2030-01-01T00:00:00Z"
FIXTURE_CLOCK_EXPIRED = "2030-01-01T01:00:00Z"
APPROVAL_TIMESTAMP = "2030-01-01T00:00:00Z"
APPROVAL_EXPIRY = "2030-01-01T00:30:00Z"

_AUDIT_PATH = None
_AUDIT_OFFSET = 0
_AUDIT_PATTERN_PATH = HERE / "approved_audit_pattern.py"
_LOADER = importlib.machinery.SourceFileLoader("saf_scoped_audit_pattern", str(_AUDIT_PATTERN_PATH))
_SPEC = importlib.util.spec_from_loader(_LOADER.name, _LOADER)
AUDIT = importlib.util.module_from_spec(_SPEC)
_LOADER.exec_module(AUDIT)


def prepare_kind(lab, temporary):
    """Runner pre-create hook: prepare only case-owned metadata audit inputs."""
    global _AUDIT_PATH
    root = Path(temporary).resolve()
    audit_root = root / "saf-0304-006-audit"
    audit_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    policy_path = audit_root / "audit-policy.yaml"
    audit_dir = audit_root / "node-audit"
    audit_dir.mkdir(mode=0o700)
    policy_path.write_text(audit_policy_text(), encoding="utf-8")
    policy_path.chmod(0o600)
    _AUDIT_PATH = audit_dir / "audit.log"
    marker = audit_root / "collector-marker"
    marker.write_text(MARKER_CONTENT + "\n")
    marker.chmod(0o444)
    config = AUDIT.kind_config_text(policy_path, audit_dir)
    marker_mount = (
        f"      - hostPath: {json.dumps(str(marker))}\n"
        f"        containerPath: {MARKER_PATH}\n"
        "        readOnly: true\n"
    )
    kind_path = audit_root / "kind.yaml"
    kind_path.write_text(config.replace("kubeadmConfigPatches:\n", marker_mount + "kubeadmConfigPatches:\n", 1))
    return kind_path


def audit_policy_text():
    """Metadata-only Pod CREATE audit in the owned exception namespace."""
    return (
        "apiVersion: audit.k8s.io/v1\n"
        "kind: Policy\n"
        "omitStages: [RequestReceived, ResponseStarted, Panic]\n"
        "rules:\n"
        "  - level: Metadata\n"
        "    verbs: [create]\n"
        f"    namespaces: [{EXCEPTION_NAMESPACE}]\n"
        "    resources:\n"
        "      - group: \"\"\n"
        "        resources: [pods]\n"
        "  - level: None\n"
    )


def capture_audit_start():
    """Remember EOF so only this case's newly appended events are considered."""
    global _AUDIT_OFFSET
    if _AUDIT_PATH is None:
        raise AssertionError("runner did not prepare the native audit log")
    _AUDIT_OFFSET = _AUDIT_PATH.stat().st_size if _AUDIT_PATH.exists() else 0


def case_audit_events():
    """Filter metadata events to exact case-owned Pod names and namespaces."""
    names = {
        (NAMESPACE, FIXTURES["hostpath_candidate"]["metadata"]["name"]),
        (NAMESPACE, FIXTURES["permitted_emptydir_candidate"]["metadata"]["name"]),
        (EXCEPTION_NAMESPACE, FIXTURES["approved_hostpath_candidate"]["metadata"]["name"]),
        (EXCEPTION_NAMESPACE, "saf-hostpath-unrelated-workload"),
    }
    result = []
    with _AUDIT_PATH.open("rb") as source:
        source.seek(_AUDIT_OFFSET)
        for raw in source:
            try:
                event = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            ref = event.get("objectRef") or {}
            expected_path = f"/api/v1/namespaces/{EXCEPTION_NAMESPACE}/pods"
            uri = urlsplit(event.get("requestURI", ""))
            fields = parse_qs(uri.query)
            if (
                event.get("stage") == "ResponseComplete"
                and event.get("verb") == "create"
                and uri.path == expected_path
                and fields.get("fieldManager") == [OBSERVED_MANAGER]
                and ref.get("apiGroup", "") == ""
                and ref.get("resource") == "pods"
                and not ref.get("subresource")
                and (ref.get("namespace"), ref.get("name")) in names
            ):
                result.append(event)
    return result


def server_dry_run(lab, pod):
    """Submit only a server-side dry-run CREATE request for a fixture Pod."""
    return lab.kubectl(
        "-n", NAMESPACE,
        "create", "-f", "-", "--dry-run=server", "-o", "json",
        payload=json.dumps(pod), allow_failure=True,
    )


def server_dry_run_as(lab, pod, identity, *, synchronize=False):
    """Submit a server-side dry-run as a policy-authorized fixture identity."""
    manager = SYNC_MANAGER if synchronize else OBSERVED_MANAGER
    return lab.kubectl(
        "--as=" + identity,
        "-n", pod["metadata"]["namespace"],
        "create", "-f", "-", "--dry-run=server", f"--field-manager={manager}", "-o", "json",
        payload=json.dumps(pod), allow_failure=True,
    )


def create_object(lab, obj):
    """Create a case-owned policy or approval object from inline JSON."""
    namespace = obj.get("metadata", {}).get("namespace")
    args = ("-n", namespace) if namespace else ()
    return lab.kubectl(
        *args, "create", "-f", "-", payload=json.dumps(obj),
    )


def denied_for_hostpath(result):
    message = result.stderr
    return (
        result.returncode != 0
        and "(Forbidden)" in message
        and DENIAL_MARKER in message
        and f"baseline:{POLICY_VERSION}" in message
        and "hostPath volumes" in message
    )


def denied_by_exception_policy(result):
    message = result.stderr
    return (
        result.returncode != 0
        and "(Forbidden)" in message
        and "validatingadmissionpolicy" in message.lower()
        and POLICY_NAME in message
        and VAP_DENIAL_MARKER in message
    )


def denied_for_missing_approval(result):
    message = result.stderr
    return (
        result.returncode != 0
        and "validatingadmissionpolicy" in message.lower()
        and POLICY_NAME in message
        and "no params found for policy binding" in message
    )


def approval_crd():
    return {
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {"name": "hostpathapprovals.saf.example"},
        "spec": {
            "group": "saf.example",
            "scope": "Namespaced",
            "names": {
                "plural": "hostpathapprovals",
                "singular": "hostpathapproval",
                "kind": "HostPathApproval",
                "shortNames": ["hpa"],
            },
            "versions": [{
                "name": "v1",
                "served": True,
                "storage": True,
                "schema": {"openAPIV3Schema": {
                    "type": "object",
                    "required": ["spec"],
                    "properties": {"spec": {
                        "type": "object",
                        "required": [
                            "requestIdentity", "namespace", "workloadName",
                            "hostPath", "readOnly", "approvalId",
                            "approvalTimestamp", "expiresAt",
                        ],
                        "properties": {
                            "requestIdentity": {"type": "string"},
                            "namespace": {"type": "string"},
                            "workloadName": {"type": "string"},
                            "hostPath": {"type": "string"},
                            "readOnly": {"type": "boolean"},
                            "approvalId": {"type": "string"},
                            "approvalTimestamp": {"type": "string", "format": "date-time"},
                            "expiresAt": {"type": "string", "format": "date-time"},
                        },
                    }},
                }},
            }],
        },
    }


def approval_record(path=MARKER_PATH):
    return {
        "apiVersion": "saf.example/v1",
        "kind": "HostPathApproval",
        "metadata": {
            "name": APPROVAL_NAME,
            "namespace": EXCEPTION_NAMESPACE,
        },
        "spec": {
            "requestIdentity": APPROVED_IDENTITY,
            "namespace": EXCEPTION_NAMESPACE,
            "workloadName": "saf-hostpath-approved-collector",
            "hostPath": path,
            "readOnly": True,
            "approvalId": "case-record-0304-006-a",
            "approvalTimestamp": APPROVAL_TIMESTAMP,
            "expiresAt": APPROVAL_EXPIRY,
        },
    }


def parse_fixture_time(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise AssertionError("fixture timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def reconcile_fixture_expiry(lab, fixture_clock):
    """Revoke only this case's approval when its explicit fixture clock expires."""
    approval = json.loads(lab.kubectl(
        "-n", EXCEPTION_NAMESPACE, "get", "hostpathapproval", APPROVAL_NAME, "-o", "json"
    ).stdout)
    spec = approval.get("spec") or {}
    if spec.get("approvalId") != "case-record-0304-006-a":
        raise AssertionError("refusing to reconcile an approval not owned by this fixture")
    approved_at = parse_fixture_time(spec["approvalTimestamp"])
    expires_at = parse_fixture_time(spec["expiresAt"])
    now = parse_fixture_time(fixture_clock)
    if not approved_at < expires_at:
        raise AssertionError("approval expiry must follow its approval timestamp")
    if now < approved_at:
        raise AssertionError("fixture clock cannot precede the approval timestamp")
    if now < expires_at:
        return False
    lab.kubectl("-n", EXCEPTION_NAMESPACE, "delete", "hostpathapproval", APPROVAL_NAME)
    return True


def exception_policy():
    expression = (
        "request.userInfo.username == params.spec.requestIdentity && "
        "(!has(object.spec.hostNetwork) || !object.spec.hostNetwork) && "
        "(!has(object.spec.hostPID) || !object.spec.hostPID) && "
        "(!has(object.spec.hostIPC) || !object.spec.hostIPC) && "
        "has(object.spec.automountServiceAccountToken) && !object.spec.automountServiceAccountToken && "
        "has(object.metadata.annotations) && "
        "object.metadata.annotations['saf.example/approval-id'] == params.spec.approvalId && "
        "object.metadata.namespace == params.spec.namespace && "
        "object.metadata.name == params.spec.workloadName && "
        "params.spec.readOnly == true && "
        "object.spec.volumes.size() == 1 && "
        "object.spec.containers.size() == 1 && "
        "(!has(object.spec.initContainers) || object.spec.initContainers.size() == 0) && "
        "object.spec.volumes.all(v, has(v.hostPath) && "
        f"v.hostPath.path == '{MARKER_PATH}' && "
        "v.hostPath.path == params.spec.hostPath && "
        "has(v.hostPath.type) && v.hostPath.type == 'File') && "
        "object.spec.containers.all(c, has(c.securityContext) && "
        "(!has(c.securityContext.privileged) || !c.securityContext.privileged) && "
        "has(c.securityContext.runAsNonRoot) && c.securityContext.runAsNonRoot && "
        "has(c.securityContext.allowPrivilegeEscalation) && !c.securityContext.allowPrivilegeEscalation && "
        "has(c.securityContext.readOnlyRootFilesystem) && c.securityContext.readOnlyRootFilesystem && "
        "has(c.securityContext.capabilities) && c.securityContext.capabilities.drop == ['ALL'] && "
        "(!has(c.securityContext.capabilities.add) || c.securityContext.capabilities.add.size() == 0) && "
        "c.volumeMounts.size() == 1 && c.volumeMounts.all(m, "
        "m.name == object.spec.volumes[0].name && m.mountPath == '/collector-marker' && "
        "has(m.readOnly) && m.readOnly && !has(m.subPath) && !has(m.subPathExpr)))"
    )
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": POLICY_NAME},
        "spec": {
            "failurePolicy": "Fail",
            "paramKind": {
                "apiVersion": "saf.example/v1",
                "kind": "HostPathApproval",
            },
            "matchConstraints": {"resourceRules": [{
                "apiGroups": [""],
                "apiVersions": ["v1"],
                "operations": ["CREATE"],
                "resources": ["pods"],
                "scope": "Namespaced",
            }]},
            "validations": [{
                "expression": expression,
                "message": VAP_DENIAL_MARKER,
                "reason": "Forbidden",
            }],
        },
    }


def exception_binding():
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": POLICY_NAME},
        "spec": {
            "policyName": POLICY_NAME,
            "validationActions": ["Deny"],
            "paramRef": {
                "name": APPROVAL_NAME,
                "namespace": EXCEPTION_NAMESPACE,
                "parameterNotFoundAction": "Deny",
            },
            "matchResources": {"namespaceSelector": {"matchLabels": {
                "saf.example/hostpath-exception": "case-owned",
            }}},
        },
    }


def admitted_pod(result, expected_name):
    if result.returncode != 0:
        return False, result.stderr.strip()
    try:
        admitted = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        return False, f"server dry-run returned invalid JSON: {error}"
    return (
        admitted.get("kind") == "Pod"
        and admitted.get("metadata", {}).get("name") == expected_name,
        {"kind": admitted.get("kind"), "name": admitted.get("metadata", {}).get("name")},
    )


def run(lab):
    capture_audit_start()
    hostpath = FIXTURES["hostpath_candidate"]
    permitted = FIXTURES["permitted_emptydir_candidate"]
    approved = FIXTURES["approved_hostpath_candidate"]

    # Both probes are dry-run CREATE requests. The initial namespace is created
    # without Pod Security labels to establish that the API accepts the same
    # harmless hostPath-shaped Pod before the intended admission policy applies.
    lab.kubectl("create", "namespace", NAMESPACE)
    red = server_dry_run(lab, hostpath)
    red_ok, red_observed = admitted_pod(red, hostpath["metadata"]["name"])
    lab.check(
        "red",
        "Unlabeled fixture namespace admits the hostPath-shaped server dry-run",
        red_ok,
        red_observed,
    )

    lab.kubectl(
        "label", "namespace", NAMESPACE,
        "pod-security.kubernetes.io/enforce=baseline",
        f"pod-security.kubernetes.io/enforce-version={POLICY_VERSION}",
        "pod-security.kubernetes.io/audit=baseline",
        f"pod-security.kubernetes.io/audit-version={POLICY_VERSION}",
        "pod-security.kubernetes.io/warn=baseline",
        f"pod-security.kubernetes.io/warn-version={POLICY_VERSION}",
    )
    green = server_dry_run(lab, hostpath)
    lab.check(
        "green",
        "Pinned Baseline denies the same hostPath dry-run for the hostPath reason",
        denied_for_hostpath(green),
        green.stderr.strip(),
    )

    positive = server_dry_run(lab, permitted)
    positive_ok, positive_observed = admitted_pod(
        positive, permitted["metadata"]["name"]
    )
    lab.check(
        "positive",
        "Pinned Baseline admits a harmless non-hostPath emptyDir dry-run",
        positive_ok,
        positive_observed,
    )

    # This second namespace deliberately uses PSA Privileged so native PSA does
    # not block the one exception-shaped request. The case-owned VAP binding is
    # the scoped allowlist gate. Only the approved marker request is persisted.
    lab.kubectl("create", "namespace", EXCEPTION_NAMESPACE)
    lab.kubectl(
        "label", "namespace", EXCEPTION_NAMESPACE,
        "pod-security.kubernetes.io/enforce=privileged",
        "saf.example/hostpath-exception=case-owned",
    )
    create_object(lab, approval_crd())
    lab.kubectl(
        "wait", "--for=condition=Established", "--timeout=60s",
        "crd/hostpathapprovals.saf.example",
    )
    create_object(lab, approval_record())
    initial_approval_active = not reconcile_fixture_expiry(lab, FIXTURE_CLOCK_APPROVED)
    lab.check(
        "positive",
        "The timestamped case approval remains active at the explicit pre-expiry fixture clock",
        initial_approval_active,
        {"active_at_fixture_clock": initial_approval_active},
    )
    lab.kubectl(
        "create", "serviceaccount", "saf-hostpath-requester",
        "-n", EXCEPTION_NAMESPACE,
    )
    lab.kubectl(
        "create", "serviceaccount", "saf-hostpath-unapproved",
        "-n", EXCEPTION_NAMESPACE,
    )
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "hostpath-dryrun-probes", "namespace": EXCEPTION_NAMESPACE},
        "rules": [
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]},
            {"apiGroups": ["saf.example"], "resources": ["hostpathapprovals"],
             "resourceNames": [APPROVAL_NAME], "verbs": ["get"]},
        ],
    }
    role_binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {"name": "hostpath-dryrun-probes", "namespace": EXCEPTION_NAMESPACE},
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": "hostpath-dryrun-probes",
        },
        "subjects": [
            {"kind": "ServiceAccount", "name": "saf-hostpath-requester", "namespace": EXCEPTION_NAMESPACE},
            {"kind": "ServiceAccount", "name": "saf-hostpath-unapproved", "namespace": EXCEPTION_NAMESPACE},
        ],
    }
    create_object(lab, role)
    create_object(lab, role_binding)
    create_object(lab, exception_policy())
    create_object(lab, exception_binding())

    def wait_for_decision(probe, identity, ready):
        for _ in range(30):
            result = server_dry_run_as(lab, probe, identity, synchronize=True)
            if ready(result):
                return
            time.sleep(0.5)
        lab.block("The scoped host-volume admission decision did not settle: " + result.stderr.strip())

    wait_for_decision(approved, UNAPPROVED_IDENTITY, denied_by_exception_policy)
    assert not reconcile_fixture_expiry(lab, FIXTURE_CLOCK_APPROVED)
    exception_positive = server_dry_run_as(lab, approved, APPROVED_IDENTITY)
    exception_ok, exception_observed = admitted_pod(
        exception_positive, approved["metadata"]["name"]
    )
    lab.check(
        "positive",
        "Case-approved identity and exact read-only hostPath request are admitted by server dry-run",
        exception_ok,
        exception_observed,
    )

    # A missing parameter record must fail closed at the native admission layer.
    lab.kubectl(
        "delete", "hostpathapproval", APPROVAL_NAME, "-n", EXCEPTION_NAMESPACE,
    )
    wait_for_decision(approved, APPROVED_IDENTITY, denied_for_missing_approval)
    absent = server_dry_run_as(lab, approved, APPROVED_IDENTITY)
    lab.check(
        "green",
        "Missing case approval is denied with the native admission reason",
        denied_for_missing_approval(absent),
        {"native_parameter_missing_denial": denied_for_missing_approval(absent)},
    )
    create_object(lab, approval_record())

    # A mismatched approval path stands in for a stale/misaligned approval. The
    # inert alternate path is never opened or mounted by a running workload.
    lab.kubectl(
        "delete", "hostpathapproval", APPROVAL_NAME, "-n", EXCEPTION_NAMESPACE,
    )
    create_object(lab, approval_record("/tmp/saf-hostpath-other"))
    wait_for_decision(approved, APPROVED_IDENTITY, denied_by_exception_policy)
    mismatched = server_dry_run_as(lab, approved, APPROVED_IDENTITY)
    lab.check(
        "green",
        "Mismatched approval path is denied with the native admission reason",
        denied_by_exception_policy(mismatched),
        {"native_policy_denial": denied_by_exception_policy(mismatched)},
    )
    lab.kubectl(
        "delete", "hostpathapproval", APPROVAL_NAME, "-n", EXCEPTION_NAMESPACE,
    )
    create_object(lab, approval_record())

    wait_for_decision(approved, APPROVED_IDENTITY, lambda result: result.returncode == 0)
    writable = json.loads(json.dumps(approved))
    writable["spec"]["containers"][0]["volumeMounts"][0]["readOnly"] = False
    writable_result = server_dry_run_as(lab, writable, APPROVED_IDENTITY)
    lab.check("green", "A writable mount is denied even for the approved collector identity",
              denied_by_exception_policy(writable_result),
              {"denied_by_scoped_policy": denied_by_exception_policy(writable_result)})

    unauthorized_identity = server_dry_run_as(lab, approved, UNAPPROVED_IDENTITY)
    lab.check(
        "green",
        "An RBAC-authorized but unapproved request identity is denied by native admission",
        denied_by_exception_policy(unauthorized_identity),
        {"native_policy_denial": denied_by_exception_policy(unauthorized_identity)},
    )

    unrelated = json.loads(json.dumps(approved))
    unrelated["metadata"]["name"] = "saf-hostpath-unrelated-workload"
    unrelated_result = server_dry_run_as(lab, unrelated, APPROVED_IDENTITY)
    lab.check(
        "green",
        "An unrelated workload name is denied by native admission",
        denied_by_exception_policy(unrelated_result),
        {"native_policy_denial": denied_by_exception_policy(unrelated_result)},
    )

    live = lab.kubectl("--as=" + APPROVED_IDENTITY, "-n", EXCEPTION_NAMESPACE,
                       "create", "-f", "-", f"--field-manager={OBSERVED_MANAGER}", "-o", "json",
                       payload=json.dumps(approved))
    live_ok, _ = admitted_pod(live, approved["metadata"]["name"])
    name = approved["metadata"]["name"]
    lab.kubectl("-n", EXCEPTION_NAMESPACE, "wait", "--for=jsonpath={.status.phase}=Succeeded",
                f"pod/{name}", "--timeout=65s", timeout=75)
    contents = lab.kubectl("-n", EXCEPTION_NAMESPACE, "logs", name, "-c", "probe").stdout
    marker_ok = contents.strip().splitlines() == ["readonly-mount-confirmed", MARKER_CONTENT]
    lab.check("positive", "The approved unprivileged Pod reads only its case-owned marker on a read-only mount",
              live_ok and marker_ok, {"approved_request_persisted": live_ok, "exact_marker_and_mount_mode": marker_ok})
    lab.kubectl("-n", EXCEPTION_NAMESPACE, "delete", "pod", name, "--wait=true", "--timeout=20s", timeout=30)

    revoked = reconcile_fixture_expiry(lab, FIXTURE_CLOCK_EXPIRED)
    wait_for_decision(approved, APPROVED_IDENTITY, denied_for_missing_approval)
    expired = server_dry_run_as(lab, approved, APPROVED_IDENTITY)
    lab.check(
        "green",
        "The same exact request is denied after controlled-clock expiry revokes its owned approval",
        revoked and denied_for_missing_approval(expired),
        {"owned_approval_revoked": revoked,
         "native_parameter_missing_denial": denied_for_missing_approval(expired)},
    )

    persisted = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pods", "-o", "json").stdout)["items"]
    exception_persisted = json.loads(
        lab.kubectl("-n", EXCEPTION_NAMESPACE, "get", "pods", "-o", "json").stdout
    )["items"]
    lab.check(
        "positive",
        "No Pod remains after removing the sole approved runtime sample",
        not persisted and not exception_persisted,
        {"policy_namespace_pods": len(persisted), "exception_namespace_pods": len(exception_persisted)},
    )

    expected_audit = [
        (APPROVED_IDENTITY, "create", 201, True),
        (APPROVED_IDENTITY, "create", 422, True),
        (APPROVED_IDENTITY, "create", 403, True),
        (APPROVED_IDENTITY, "create", 403, True),
        (UNAPPROVED_IDENTITY, "create", 403, True),
        (APPROVED_IDENTITY, "create", 403, True),
        (APPROVED_IDENTITY, "create", 201, False),
        (APPROVED_IDENTITY, "create", 422, True),
    ]
    events = []
    for _ in range(20):
        if _AUDIT_PATH.exists():
            events = case_audit_events()
        if len(events) >= len(expected_audit):
            break
        time.sleep(0.5)
    rows = [{
        "audit_id": event.get("auditID"),
        "level": event.get("level"),
        "identity": AUDIT.effective_username(event),
        "pod": event["objectRef"]["name"],
        "namespace": event["objectRef"]["namespace"],
        "verb": event["verb"],
        "code": event.get("responseStatus", {}).get("code"),
        "dry_run": "dryRun=All" in urlsplit(event["requestURI"]).query.split("&"),
        "payload_absent": "requestObject" not in event and "responseObject" not in event,
    } for event in events]
    (lab.evidence / "host-volume-approval-audit.json").write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n")
    audit_ok = all(row["level"] == "Metadata" for row in rows)
    try:
        AUDIT.assert_fixture_audit_events(events, expected_audit)
    except AssertionError:
        audit_ok = False
    lab.check(
        "positive",
        "Native Metadata audit matches the case-owned permitted and denied host-volume decisions",
        audit_ok,
        {"matched_metadata_events": audit_ok, "observed_count": len(rows), "expected_count": len(expected_audit)},
    )
