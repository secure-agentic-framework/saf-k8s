"""Observe effective privileges and corroborating usage without treating absent use as drift."""

import json
from pathlib import Path
import time

from fixtures import container, pod, ready

NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
NS = "saf-test"
ACCOUNT = "fixture-drift-workload"
ROLE = "fixture-drift-grant"
MAIN = "fixture-required-reader"
EXCEPTION = "fixture-approved-unexercised"
EXCESS = "fixture-unapproved-neighbor"
RESOURCES = (MAIN, EXCEPTION, EXCESS)
MARKER = "owned-public-authorization-marker"
USER = f"system:serviceaccount:{NS}:{ACCOUNT}"
AUDIT = "/etc/kubernetes/saf-scope-drift"
CURL = ("docker.io/curlimages/curl:8.17.0@sha256:"
        "935d9100e9ba842cdb060de42472c7ca90cfe9a7c96e4dacb55e79e560b3ff40")
BASE = "https://kubernetes.default.svc"
SELF_REVIEW = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
SCOPE = (
    "Compare actual effective Kubernetes privileges, approved inventory and exception evidence, "
    "and captured metadata from a known workload's successful or denied use. Unknown telemetry "
    "and provider-cloud IAM coverage require separate evidence."
)


def policy_file(lab):
    return lab.kubeconfig.parent / "drift-audit"


def prepare_kind(lab, temporary):
    audit = policy_file(lab)
    audit.mkdir()
    policy = {"apiVersion": "audit.k8s.io/v1", "kind": "Policy",
              "omitStages": ["RequestReceived"], "rules": [{"level": "Metadata", "users": [USER],
                  "namespaces": [NS], "verbs": ["get"], "resources": [{"group": "", "resources": ["configmaps"]}]},
                  {"level": "None"}]}
    (audit / "policy.json").write_text(json.dumps(policy))
    kind = temporary / "fixture-drift-kind.yaml"
    kind.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: {json.dumps(str(audit))}
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
      value: {AUDIT}/audit.jsonl
    - name: audit-log-mode
      value: blocking
    extraVolumes:
    - name: saf-scope-drift-audit
      hostPath: {AUDIT}
      mountPath: {AUDIT}
      pathType: Directory
""")
    return kind


def identity(lab):
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": ACCOUNT},
                "automountServiceAccountToken": False})
    unit = container("app", image=CURL, command=["sh", "-c", "sleep 360"],
                     volumeMounts=[{"name": "identity", "mountPath": "/identity", "readOnly": True}])
    credential = {"serviceAccountToken": {"path": "token", "expirationSeconds": 600}}
    ca = {"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}}
    lab.create(pod(ACCOUNT, [unit], serviceAccountName=ACCOUNT, automountServiceAccountToken=False,
                   volumes=[{"name": "identity", "projected": {"sources": [credential, ca]}}]))


def private_api(lab, target, body=""):
    shell = r'''set -eu
umask 077
conf=$(mktemp)
trap 'rm -f "$conf"' EXIT
printf 'header = "Authorization: Bearer %s"\n' "$(cat /identity/token)" >"$conf"
url=$1
body=$2
if [ -n "$body" ]; then
  set -- --request POST --header 'Content-Type: application/json' --data "$body"
else
  set --
fi
curl --silent --show-error --max-time 7 --cacert /identity/ca.crt --config "$conf" \
     --write-out '\n%{http_code}\n' "$@" "$url"
'''
    out = lab.kubectl("exec", ACCOUNT, "--", "sh", "-c", shell, "fixture-probe", BASE + target, body)
    raw, code = out.stdout.strip().rsplit("\n", 1)
    return int(code), json.loads(raw)


def read_test(lab, name):
    status, response = private_api(lab, f"/api/v1/namespaces/{NS}/configmaps/{name}")
    return status, response.get("data", {}).get("marker") == MARKER


def effective(lab):
    permissions = {}
    for resource in RESOURCES:
        payload = {"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
                   "spec": {"resourceAttributes": {"namespace": NS, "verb": "get", "resource": "configmaps",
                                                   "name": resource}}}
        code, doc = private_api(lab, SELF_REVIEW, json.dumps(payload))
        if code != 201 or "status" not in doc:
            lab.block("Kubernetes did not return the scoped authorization decision")
        permissions[resource] = bool(doc["status"].get("allowed", False))
    return permissions


def rights(names):
    return [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": names, "verbs": ["get"]}]


def set_rights(lab, names):
    lab.kubectl("patch", "role/" + ROLE, "--type=merge", "-p", json.dumps({"rules": rights(names)}), "-o", "name")


def ledger(lab):
    filename = policy_file(lab) / "audit.jsonl"
    if not filename.exists():
        return None
    rows = []
    for line in filename.read_text().splitlines():
        event = json.loads(line)
        reference = event.get("objectRef") or {}
        if event.get("stage") == "ResponseComplete" and reference.get("name") in RESOURCES:
            rows.append((reference["name"], event["responseStatus"]["code"], event["user"]["username"]))
    return rows


def assessment(granted, logs):
    approved = {MAIN, EXCEPTION}
    over = sorted(name for name, allowed in granted.items() if allowed and name not in approved)
    if logs is None:
        return {"unapproved_grants": over, "usage_known": False, "unused_approved": None}
    observed = {name for name, status, actor in logs if status == 200 and actor == USER}
    if MAIN not in observed:
        return {"unapproved_grants": over, "usage_known": False, "unused_approved": None}
    return {"unapproved_grants": over, "usage_known": True, "unused_approved": sorted(approved - observed)}


def run(lab):
    identity(lab)
    for name in RESOURCES:
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "data": {"marker": MARKER}})
    api = "rbac.authorization.k8s.io/v1"
    lab.create({"apiVersion": api, "kind": "Role", "metadata": {"name": ROLE}, "rules": rights([MAIN, EXCEPTION])})
    lab.create({"apiVersion": api, "kind": "RoleBinding", "metadata": {"name": ROLE},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": ROLE},
                "subjects": [{"kind": "ServiceAccount", "name": ACCOUNT, "namespace": NS}]})
    ready(lab, ACCOUNT)
    good = read_test(lab, MAIN) == (200, True)
    rejected = read_test(lab, EXCESS)[0] == 403
    initial = effective(lab)
    baseline = assessment(initial, ledger(lab))
    lab.check("red", "Known usage leaves the approved standby permission unused and the unrelated resource denied",
              good and rejected and baseline == {"unapproved_grants": [], "usage_known": True, "unused_approved": [EXCEPTION]},
              {"required_read": good, "neighbor_initially_denied": rejected, "baseline": baseline})

    set_rights(lab, list(RESOURCES))
    deadline = time.monotonic() + 20
    granted = initial
    while time.monotonic() < deadline:
        granted = effective(lab)
        if granted[EXCESS]:
            break
        time.sleep(.5)
    report = assessment(granted, ledger(lab))
    unavailable = assessment(granted, None)
    lab.check("green", "The monitor detects an effective unapproved grant while keeping the approved standby and missing usage distinct",
              report == {"unapproved_grants": [EXCESS], "usage_known": True, "unused_approved": [EXCEPTION]}
              and unavailable == {"unapproved_grants": [EXCESS], "usage_known": False, "unused_approved": None},
              {"after_scope_change": report, "without_usage_records": unavailable})

    set_rights(lab, [MAIN, EXCEPTION])
    deadline = time.monotonic() + 20
    restored = False
    while time.monotonic() < deadline:
        restored = read_test(lab, EXCESS)[0] == 403
        if restored:
            break
        time.sleep(.5)
    still_good = read_test(lab, MAIN) == (200, True)
    lab.check("positive", "Restoring the reviewed grant removes excess while preserving the required workload decision",
              restored and still_good,
              {"excess_denied_after_restore": restored, "required_read_preserved": still_good})
    (lab.evidence / "credential-scope-drift-observations.json").write_text(json.dumps({
        "baseline": baseline, "drift_report": report, "missing_event_source": unavailable,
        "required_read_preserved": still_good, "excess_revoked": restored,
        "continuous_external_iam_tested": False,
    }, indent=2) + "\n")
