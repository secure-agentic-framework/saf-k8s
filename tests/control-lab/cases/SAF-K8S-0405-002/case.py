"""Verify alert classification and delivery for owned RBAC audit events."""
import json
from pathlib import Path
import time

NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
NAMESPACE = "saf-test"
ROLE = "fixture-benign-review-reader"
APPROVED = "fixture-approved-reader-binding"
REVIEW = "fixture-unapproved-reader-binding"
WORKLOAD = "system:serviceaccount:saf-test:fixture-reader"
IDENTITY_SA = "fixture-projected-audit-reader"
IDENTITY_ROLE = "fixture-projected-audit-role"
IDENTITY_BINDING = "fixture-projected-audit-binding"
IDENTITY_POD = "fixture-projected-audit-pod"
IDENTITY_ALLOWED = "fixture-identity-allowed"
IDENTITY_DENIED = "fixture-identity-denied"
IDENTITY_NAME = f"system:serviceaccount:{NAMESPACE}:{IDENTITY_SA}"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
AUDIT = "/etc/kubernetes/saf-fixture-rbac-audit"
RBAC = "rbac.authorization.k8s.io/v1"
SCOPE = (
    "Metadata-only Kubernetes audit records scoped RoleBinding activity and two named reads "
    "from a case-owned Pod using its projected identity. The case compares the allowed and "
    "denied API responses, attributes both events, and routes the denied result to a local queue."
)


def prepare_kind(lab, temporary):
    destination = temporary / "fixture-rbac-audit"
    destination.mkdir()
    policy = {"apiVersion": "audit.k8s.io/v1", "kind": "Policy", "omitStages": ["RequestReceived"],
              "rules": [{"level": "Metadata", "users": [IDENTITY_NAME],
                         "namespaces": [NAMESPACE], "resourceNames": [IDENTITY_ALLOWED, IDENTITY_DENIED],
                         "verbs": ["get"],
                         "resources": [{"group": "", "resources": ["configmaps"]}]},
                        {"level": "Metadata", "namespaces": [NAMESPACE],
                         "verbs": ["create", "patch", "delete"],
                         "resources": [{"group": "rbac.authorization.k8s.io", "resources": ["rolebindings"]}]},
                        {"level": "None"}]}
    (destination/"policy.json").write_text(json.dumps(policy))
    profile = temporary / "fixture-rbac-kind.yaml"
    profile.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: {json.dumps(str(destination))}
    containerPath: {AUDIT}
kubeadmConfigPatches:
- |
  apiVersion: kubeadm.k8s.io/v1beta4
  kind: ClusterConfiguration
  apiServer:
    extraArgs:
    - name: audit-policy-file
      value: {AUDIT}/policy.json
    - name: audit-log-path
      value: {AUDIT}/events.jsonl
    - name: audit-log-mode
      value: blocking
    extraVolumes:
    - name: saf-fixture-rbac-audit
      hostPath: {AUDIT}
      mountPath: {AUDIT}
      pathType: Directory
""")
    return profile


def binding(lab, name):
    lab.create({"apiVersion": RBAC, "kind": "RoleBinding", "metadata": {"name": name},
                "roleRef": {"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":ROLE},
                "subjects":[{"kind":"ServiceAccount","name":"fixture-reader","namespace":NAMESPACE}]})


def queue(lab):
    out = lab.kubectl("get", "configmap", "fixture-rbac-review-queue", "-o", "json").stdout
    return json.loads(json.loads(out)["data"]["alerts"])


def records(lab):
    path = Path(lab.kubeconfig).parent/"fixture-rbac-audit"/"events.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def classify(events, living):
    signals = []
    reviewed = []
    for event in events:
        reference = event.get("objectRef") or {}
        name = reference.get("name")
        if event.get("stage") != "ResponseComplete" or name not in living:
            continue
        code = (event.get("responseStatus") or {}).get("code")
        user = (event.get("impersonatedUser") or event.get("user") or {}).get("username")
        if event["verb"] == "create" and code == 201:
            if name == APPROVED and living[name] == ROLE:
                reviewed.append(name)
            elif living[name] == ROLE:
                signals.append({"finding": "admin_change_requires_review", "resource": name, "decision": "accepted"})
        elif event["verb"] == "patch" and code == 403 and user == WORKLOAD:
            signals.append({"finding": "denied_binding_mutation", "resource": name, "decision": "denied"})
    return sorted(signals, key=lambda item: item["finding"]), sorted(reviewed)


def audit_identity_reads(events):
    """Return only minimal facts for the two exact projected-identity GETs."""
    matches = {}
    expected_names = {IDENTITY_ALLOWED, IDENTITY_DENIED}
    for event in events:
        ref = event.get("objectRef") or {}
        name = ref.get("name")
        if (event.get("stage") != "ResponseComplete"
                or event.get("level") != "Metadata"
                or event.get("verb") != "get"
                or ref.get("resource") != "configmaps"
                or ref.get("namespace") != NAMESPACE
                or name not in expected_names
                or (event.get("user") or {}).get("username") != IDENTITY_NAME):
            continue
        code = (event.get("responseStatus") or {}).get("code")
        matches.setdefault(name, []).append({
            "code": code,
            "audit_id_present": bool(event.get("auditID")),
            "metadata_only": "requestObject" not in event and "responseObject" not in event,
        })
    return matches


def add_projected_identity_read(lab):
    """Exercise one permitted and one denied API read through an actual Pod token."""
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount",
                "metadata": {"name": IDENTITY_SA, "namespace": NAMESPACE},
                "automountServiceAccountToken": True})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": IDENTITY_ROLE, "namespace": NAMESPACE},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                           "resourceNames": [IDENTITY_ALLOWED], "verbs": ["get"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": IDENTITY_BINDING, "namespace": NAMESPACE},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                            "name": IDENTITY_ROLE},
                "subjects": [{"kind": "ServiceAccount", "name": IDENTITY_SA,
                              "namespace": NAMESPACE}]})
    for name, marker in ((IDENTITY_ALLOWED, "owned-approved-read-marker"),
                         (IDENTITY_DENIED, "owned-denied-read-marker")):
        lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {"name": name, "namespace": NAMESPACE},
                    "data": {"marker": marker}})
    probe_text = (Path(__file__).parent / "projected_read_probe.py").read_text(encoding="utf-8")
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "fixture-projected-audit-probe", "namespace": NAMESPACE},
                "data": {"probe.py": probe_text}})
    lab.create({"apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": IDENTITY_POD, "namespace": NAMESPACE,
                             "labels": {"saf-k8s.example/fixture": "0405-002-projected-read"}},
                "spec": {"restartPolicy": "Never", "serviceAccountName": IDENTITY_SA,
                         "automountServiceAccountToken": True,
                         "containers": [{"name": "probe", "image": PYTHON_IMAGE,
                                          "command": ["python", "-c", "import time; time.sleep(3600)"],
                                          "securityContext": {"allowPrivilegeEscalation": False,
                                                              "capabilities": {"drop": ["ALL"]},
                                                              "runAsNonRoot": True, "runAsUser": 65534,
                                                              "readOnlyRootFilesystem": True,
                                                              "seccompProfile": {"type": "RuntimeDefault"}},
                                          "volumeMounts": [{"name": "probe", "mountPath": "/fixture",
                                                            "readOnly": True}]}],
                         "volumes": [{"name": "probe", "configMap": {
                             "name": "fixture-projected-audit-probe"}}]}})
    lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready",
                f"pod/{IDENTITY_POD}", "--timeout=90s", timeout=100)
    output = lab.kubectl("-n", NAMESPACE, "exec", IDENTITY_POD, "--",
                         "python", "-B", "/fixture/probe.py", timeout=30).stdout.strip()
    try:
        status = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        status = {}
    observed = audit_identity_reads(records(lab))
    allow_rows = observed.get(IDENTITY_ALLOWED, [])
    deny_rows = observed.get(IDENTITY_DENIED, [])
    output_shape = set(status) == {"allowed", "denied"} and all(
        isinstance(status.get(key), int) for key in ("allowed", "denied"))
    allowed = (output_shape and status["allowed"] == 200
               and len(allow_rows) == 1 and allow_rows[0] == {
                   "code": 200, "audit_id_present": True, "metadata_only": True})
    denied = (output_shape and status["denied"] == 403
              and len(deny_rows) == 1 and deny_rows[0] == {
                  "code": 403, "audit_id_present": True, "metadata_only": True})
    denied_signal = {"finding": "projected_identity_denied_fixture_read",
                     "identity": IDENTITY_NAME, "resource": "configmaps",
                     "name": IDENTITY_DENIED, "decision": "denied"} if denied else None
    retained = queue(lab)
    routed = retained + ([denied_signal] if denied_signal else [])
    lab.kubectl("patch", "configmap", "fixture-rbac-review-queue", "--type=merge",
                "-p", json.dumps({"data": {"alerts": json.dumps(routed)}}), "-o", "name")
    queued = queue(lab)
    delivered = queued == routed and (not denied or queued[-1:] == [denied_signal])
    result = {"allowed_projected_identity_read": allowed,
              "denied_projected_identity_read": denied,
              "denied_signal_routed": delivered,
              "probe_output_is_status_only": status == {"allowed": 200, "denied": 403},
              "audit_events_exclude_request_and_response_bodies": (
                  all(row["metadata_only"] for row in allow_rows + deny_rows))}
    lab.check("positive", "A projected ServiceAccount read produces exact metadata-only identity evidence and a bounded denial signal",
              all(result.values()), result)
    (lab.evidence / "projected-identity-read-observations.json").write_text(
        json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def run(lab):
    lab.create({"apiVersion": "v1", "kind":"ServiceAccount", "metadata":{"name":"fixture-reader"},
                "automountServiceAccountToken":False})
    lab.create({"apiVersion": RBAC, "kind":"Role", "metadata":{"name":ROLE},
                "rules": [
                    {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["public-fixture"], "verbs": ["get"]},
                    {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["rolebindings"],
                     "resourceNames": [REVIEW], "verbs": ["get"]},
                ]})
    lab.create({"apiVersion": "v1", "kind":"ConfigMap","metadata":{"name":"public-fixture"},
                "data":{"marker":"owned-public-rbac-marker"}})
    lab.create({"apiVersion": "v1", "kind":"ConfigMap","metadata":{"name":"fixture-rbac-review-queue"},
                "data":{"alerts":"[]"}})
    binding(lab, APPROVED)
    binding(lab, REVIEW)
    denied = lab.kubectl("--as="+WORKLOAD,"patch","rolebinding",REVIEW,"--type=merge",
                         "-p",'{"metadata":{"annotations":{"owner-review":"test-only"}}}',allow_failure=True)
    raw = records(lab)
    baseline = {"api_denies_ordinary_workload_mutation": denied.returncode != 0 and "(Forbidden)" in denied.stderr,
                "audit_events_present": len(raw) >= 3, "no_alert_queue_without_consumer": queue(lab) == []}
    lab.check("red", "Real audit records alone leave the review queue empty", all(baseline.values()), baseline)

    selected = {}
    for name in (APPROVED, REVIEW):
        out = lab.kubectl("get","rolebinding",name,"-o","json").stdout
        selected[name] = json.loads(out)["roleRef"]["name"]
    signals, reviewed = classify(records(lab), selected)
    lab.kubectl("patch","configmap","fixture-rbac-review-queue","--type=merge",
                "-p",json.dumps({"data":{"alerts":json.dumps(signals)}}),"-o","name")
    retained = queue(lab)
    evidence = {"approved_change_distinguished": reviewed == [APPROVED],
                "source_has_no_request_or_response_payload": all(
                    "requestObject" not in row and "responseObject" not in row for row in raw),
                "review_queue_has_distinct_decisions": retained == [
                    {"finding":"admin_change_requires_review","resource":REVIEW,"decision":"accepted"},
                    {"finding":"denied_binding_mutation","resource":REVIEW,"decision":"denied"}]}
    lab.check("green", "The detector routes the two distinct review signals using only metadata",
              all(evidence.values()),evidence)

    lab.kubectl("delete","rolebinding",REVIEW,"--wait=false")
    allowed = lab.kubectl("--as="+WORKLOAD,"get","configmap","public-fixture",
                          "-o","jsonpath={.data.marker}",allow_failure=True)
    still = {"approved_public_read_preserved": allowed.returncode==0 and allowed.stdout=="owned-public-rbac-marker",
             "incident_signals_retained": queue(lab)==retained}
    lab.check("positive", "Review can remove the unexpected fixture grant and preserve legitimate access",
              all(still.values()),still)
    add_projected_identity_read(lab)
    (lab.evidence/"rbac-audit-observations.json").write_text(json.dumps({
        "baseline":baseline,"alert_evidence":evidence,"positive":still,
    },indent=2)+"\n")
