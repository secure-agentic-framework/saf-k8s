"""Bind one synthetic reviewer approval to an immutable model digest in API audit."""
import hashlib
import json
from pathlib import Path
import tempfile
import time

from lab import NODE_IMAGE

HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
CLUSTER_SUFFIX = "-0905-051-audit"
AUDIT_FILE = "/var/log/kubernetes/audit/audit.log"
APPROVER = "saf-0905-051-approver"
REVIEWER = f"system:serviceaccount:{NAMESPACE}:{APPROVER}"
ARTIFACT = "synthetic-model-v1"
APPROVAL = "synthetic-release-approval"
MODEL_BYTES = b"SAF inert synthetic model fixture v1\n"
MODEL_SHA256 = hashlib.sha256(MODEL_BYTES).hexdigest()
DECISION = "approved"

SCOPE = (
    "Two disposable Kubernetes v1.36.1 clusters compare API auditing off and on for the same scoped "
    "approval patch. A directly authenticated reviewer ServiceAccount persists a fixed approval. "
    "The targeted control-plane audit event binds the reviewer, decision, server time, and immutable "
    "model digest to the request and persisted response."
)

POD_SCRIPT = r'''import json, os, pathlib, ssl, urllib.request
base = "https://%s:%s" % (os.environ["KUBERNETES_SERVICE_HOST"],
                          os.environ["KUBERNETES_SERVICE_PORT_HTTPS"])
root = pathlib.Path("/var/run/secrets/kubernetes.io/serviceaccount")
token = (root / "token").read_text().strip()
body = json.dumps({"data": {"reviewer": os.environ["REVIEWER"],
                            "decision": os.environ["DECISION"],
                            "model_sha256": os.environ["MODEL_SHA256"]}},
                  separators=(",", ":")).encode()
request = urllib.request.Request(
    base + "/api/v1/namespaces/saf-test/configmaps/synthetic-release-approval",
    data=body, method="PATCH",
    headers={"Authorization": "Bearer " + token,
             "Content-Type": "application/merge-patch+json"})
context = ssl.create_default_context(cafile=str(root / "ca.crt"))
with urllib.request.urlopen(request, context=context, timeout=15) as response:
    if response.status != 200:
        raise SystemExit("unexpected API status")
    response.read()
print("synthetic approval request accepted")
'''


def api(lab, cluster, kubeconfig, *args, **kwargs):
    return lab.command("kubectl", "--kubeconfig", str(kubeconfig), "--context",
                       f"kind-{cluster}", "--namespace", NAMESPACE,
                       "--request-timeout=15s", *args, **kwargs)


def fixed_resources():
    return [
        {"apiVersion": "v1", "kind": "ConfigMap",
         "metadata": {"name": ARTIFACT, "namespace": NAMESPACE},
         "immutable": True, "data": {"sha256": MODEL_SHA256,
                                      "fixture": MODEL_BYTES.decode()}},
        {"apiVersion": "v1", "kind": "ConfigMap",
         "metadata": {"name": APPROVAL, "namespace": NAMESPACE},
         "data": {"reviewer": "pending", "decision": "pending",
                  "model_sha256": "pending"}},
        {"apiVersion": "v1", "kind": "ServiceAccount",
         "metadata": {"name": APPROVER, "namespace": NAMESPACE},
         "automountServiceAccountToken": True},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
         "metadata": {"name": "saf-0905-051-review-record", "namespace": NAMESPACE},
         "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                    "resourceNames": [APPROVAL], "verbs": ["patch"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
         "metadata": {"name": "saf-0905-051-review-record", "namespace": NAMESPACE},
         "subjects": [{"kind": "ServiceAccount", "name": APPROVER, "namespace": NAMESPACE}],
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                     "name": "saf-0905-051-review-record"}},
        {"apiVersion": "v1", "kind": "Pod",
         "metadata": {"name": "saf-0905-051-approval", "namespace": NAMESPACE},
         "spec": {"restartPolicy": "Never", "serviceAccountName": APPROVER,
                  "automountServiceAccountToken": True,
                  "containers": [{"name": "request", "image": (
                      "docker.io/library/python:3.13.2-alpine@sha256:"
                      "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"),
                      "imagePullPolicy": "IfNotPresent",
                      "command": ["python", "-B", "-c", POD_SCRIPT],
                      "env": [{"name": "REVIEWER", "value": REVIEWER},
                              {"name": "DECISION", "value": DECISION},
                              {"name": "MODEL_SHA256", "value": MODEL_SHA256}],
                      "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                    "limits": {"cpu": "100m", "memory": "64Mi"}}}]}}]


def prepare_fixture(lab, cluster, kubeconfig):
    for obj in fixed_resources()[:-1]:
        api(lab, cluster, kubeconfig, "create", "-f", "-", payload=json.dumps(obj))
    pod = fixed_resources()[-1]
    api(lab, cluster, kubeconfig, "create", "-f", "-", payload=json.dumps(pod))
    api(lab, cluster, kubeconfig, "wait", "--for=jsonpath={.status.phase}=Succeeded",
        "pod/saf-0905-051-approval", "--timeout=90s", timeout=100)
    logs = api(lab, cluster, kubeconfig, "logs", "pod/saf-0905-051-approval").stdout.strip()
    stored = json.loads(api(lab, cluster, kubeconfig, "get", f"configmap/{APPROVAL}", "-o", "json").stdout)
    return logs == "synthetic approval request accepted" and stored.get("data") == expected_data()


def baseline_state(lab):
    script = (
        "set -eu; m=/etc/kubernetes/manifests/kube-apiserver.yaml; test -r $m; "
        "if grep -q -- '--audit-' $m; then flags=present; else flags=absent; fi; "
        f"if test -e {AUDIT_FILE}; then file=present; else file=absent; fi; "
        "printf 'audit_flags=%s audit_file=%s\\n' $flags $file"
    )
    return lab.command("docker", "exec", f"{lab.cluster}-control-plane", "sh", "-c", script,
                       timeout=20).stdout.strip()


def make_kind_config(root):
    audit_dir = root / "audit"
    audit_dir.mkdir()
    policy_path = HERE / "audit-policy.yaml"
    template = (HERE / "kind.yaml.in").read_text()
    path = root / "kind.yaml"
    path.write_text(template.replace("@POLICY_PATH@", json.dumps(str(policy_path)))
                    .replace("@AUDIT_DIR@", json.dumps(str(audit_dir))))
    return path, audit_dir



def expected_data():
    return {"reviewer": REVIEWER, "decision": DECISION, "model_sha256": MODEL_SHA256}


def selected_record(path):
    if not path.is_file():
        return None
    with path.open() as log:
        rows = []
        for line in log:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            ref = event.get("objectRef") or {}
            user = (event.get("user") or {}).get("username")
            if (ref.get("namespace"), ref.get("resource"), ref.get("name"), event.get("verb"),
                event.get("stage"), user) != (NAMESPACE, "configmaps", APPROVAL, "patch",
                                              "ResponseComplete", REVIEWER):
                continue
            rows.append({**{key: event.get(key) for key in (
                         "auditID", "level", "stage", "verb", "requestReceivedTimestamp", "stageTimestamp")},
                         "model_record": APPROVAL, "user": user,
                         "responseCode": (event.get("responseStatus") or {}).get("code"),
                         "request": (event.get("requestObject") or {}).get("data"),
                         "response": (event.get("responseObject") or {}).get("data")})
    return rows[0] if len(rows) == 1 else None


def valid_event(event):
    from datetime import datetime

    if not event:
        return False
    try:
        received = datetime.fromisoformat(event["requestReceivedTimestamp"].replace("Z", "+00:00"))
        completed = datetime.fromisoformat(event["stageTimestamp"].replace("Z", "+00:00"))
    except (KeyError, AttributeError, TypeError, ValueError):
        return False
    return (bool(event["auditID"]) and event["level"] == "RequestResponse" and event["responseCode"] == 200
            and event["request"] == event["response"] == expected_data()
            and received.tzinfo is not None and completed.tzinfo is not None and completed >= received)


def run(lab):
    # The normal lab runner creates saf-test and uses its ordinary, audit-disabled
    # v1.36.1 API server. Exercise the exact fixed request shape as the red probe.
    red_accepts = prepare_fixture(lab, lab.cluster, lab.kubeconfig)
    red_state = baseline_state(lab)
    red_inactive = "audit_flags=absent" in red_state and "audit_file=absent" in red_state
    lab.check("red", "The identical synthetic approval succeeds while the API server audit backend is disabled",
              red_accepts and red_inactive,
              {"approval_request_accepted": red_accepts,
               "audit_backend": "disabled" if red_inactive else "unexpected state"})

    cluster = lab.cluster + CLUSTER_SUFFIX
    with tempfile.TemporaryDirectory(prefix="saf-0905-051-") as temp:
        root = Path(temp).resolve()
        config, audit_dir = make_kind_config(root)
        kubeconfig = root / "kubeconfig"
        existing = lab.command("kind", "get", "clusters").stdout.splitlines()
        if cluster in existing:
            lab.block("Case-owned audit cluster name is already in use")
        try:
            lab.command("kind", "create", "cluster", "--name", cluster, "--image", NODE_IMAGE,
                        "--config", str(config), "--kubeconfig", str(kubeconfig),
                        "--wait", "90s", timeout=480)
            api(lab, cluster, kubeconfig, "create", "namespace", NAMESPACE)
            accepted = prepare_fixture(lab, cluster, kubeconfig)
            event = None
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                event = selected_record(audit_dir / "audit.log")
                if event:
                    (lab.evidence / "approval-audit-observation.json").write_text(
                        json.dumps(event, indent=2, sort_keys=True) + "\n")
                    break
                time.sleep(0.25)

            # Independently re-read the artifact through the API and prove that its
            # content is marked immutable; do not return fixture data in check output.
            artifact = json.loads(api(lab, cluster, kubeconfig, "get", f"configmap/{ARTIFACT}",
                                      "-o", "json").stdout)
            artifact_ok = (artifact.get("immutable") is True
                           and artifact.get("data", {}).get("sha256") == MODEL_SHA256
                           and hashlib.sha256(artifact["data"]["fixture"].encode()).hexdigest() == MODEL_SHA256)
            event_ok = valid_event(event)
            lab.check("green", "The node audit record binds the authenticated fixture actor, reviewer, decision, server time and model digest",
                      accepted and event_ok,
                      {"approval_request_accepted": accepted,
                       "node_audit_record_matches_fixed_scope": event_ok})
            lab.check("positive", "The approved digest resolves to the immutable synthetic model ConfigMap",
                      artifact_ok,
                      {"immutable_artifact_matches_approval_digest": artifact_ok})

        finally:
            lab.command("kind", "delete", "cluster", "--name", cluster,
                        "--kubeconfig", str(kubeconfig), timeout=90)
