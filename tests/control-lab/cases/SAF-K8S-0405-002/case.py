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
AUDIT = "/etc/kubernetes/saf-fixture-rbac-audit"
RBAC = "rbac.authorization.k8s.io/v1"
SCOPE = (
    "Native API audit records approved and unexpected administrative changes to a case-owned "
    "RoleBinding for public test data, and one ordinary authorization denial. The test separates "
    "audit coverage, review policy and alert delivery to an owned queue. No attack, secret access, "
    "live credential theft, production privileges, or external monitoring integration is exercised."
)


def prepare_kind(lab, temporary):
    destination = temporary / "fixture-rbac-audit"
    destination.mkdir()
    policy = {"apiVersion": "audit.k8s.io/v1", "kind": "Policy", "omitStages": ["RequestReceived"],
              "rules": [{"level": "Metadata", "namespaces": [NAMESPACE],
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
    (lab.evidence/"rbac-audit-observations.json").write_text(json.dumps({
        "baseline":baseline,"alert_evidence":evidence,"positive":still,
    },indent=2)+"\n")
