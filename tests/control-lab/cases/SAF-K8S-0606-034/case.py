"""Review an approved fixture action against native audit and external records."""
from contextlib import contextmanager
import base64
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from lab import NODE_IMAGE

HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-0606-034-fixture"
SERVICE_ACCOUNT = "fixture-emergency-operator"
USERNAME = f"system:serviceaccount:{NAMESPACE}:{SERVICE_ACCOUNT}"
AUDIT_FILE = "/var/log/kubernetes/audit/audit.log"
CLUSTER_SUFFIX = "-breakglass-audit"
SCOPE = (
    "One disposable Kind v1.36.1 API server, one isolated namespace, and one pre-issued, "
    "short-lived ServiceAccount token. The ServiceAccount can patch only two named inert "
    "ConfigMaps. Both actions use normal HTTPS API PATCH requests. Native audit events are "
    "matched to the response Audit-ID; a separate case-owned fixture procedure joins the "
    "approved action to that event. No workload Pods are created. This does not prove "
    "production policy coverage, durable audit retention, real human approval, review, or GitOps controls."
)


def fixtures():
    return json.loads((HERE / "fixtures.json").read_text())


def incident_record():
    return json.loads((HERE / "incident-approval.json").read_text())


def kubectl_args(kubeconfig):
    return ["kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{CLUSTER_NAME}",
            "--namespace", NAMESPACE, "--request-timeout=20s"]


def admin_create(lab, kubeconfig, obj):
    result = lab.command(*kubectl_args(kubeconfig), "create", "-f", "-", "-o", "json",
                         payload=json.dumps(obj), timeout=25)
    created = json.loads(result.stdout)
    return (created.get("kind") == obj["kind"]
            and created.get("metadata", {}).get("name") == obj["metadata"]["name"])


def audit_events(audit_dir):
    path = audit_dir / "audit.log"
    if not path.is_file():
        return []
    events = []
    with path.open() as stream:
        for line in stream:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def wait_for_audit_event(audit_dir, audit_id, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        matches = [event for event in audit_events(audit_dir) if event.get("auditID") == audit_id]
        if any(event.get("stage") == "ResponseComplete" for event in matches):
            return matches
        time.sleep(0.2)
    return [event for event in audit_events(audit_dir) if event.get("auditID") == audit_id]


def summarize(event):
    ref = event.get("objectRef") or {}
    return {
        "auditID": event.get("auditID"), "stage": event.get("stage"),
        "level": event.get("level"), "verb": event.get("verb"),
        "username": (event.get("user") or {}).get("username"),
        "namespace": ref.get("namespace"), "resource": ref.get("resource"),
        "name": ref.get("name"), "responseCode": (event.get("responseStatus") or {}).get("code"),
        "requestObjectPresent": "requestObject" in event,
    }


def request_context(kubeconfig_json):
    config = json.loads(kubeconfig_json)
    cluster = config["clusters"][0]["cluster"]
    ca_pem = base64.b64decode(cluster["certificate-authority-data"]).decode()
    ca = ssl.create_default_context(cadata=ca_pem)
    return cluster["server"].rstrip("/"), ca


def patch_configmap(server, ca, token, name, patch_body):
    path = f"/api/v1/namespaces/{NAMESPACE}/configmaps/{name}"
    request = Request(server + path, data=json.dumps(patch_body, separators=(",", ":")).encode(),
                      method="PATCH", headers={
                          "Authorization": f"Bearer {token}",
                          "Content-Type": "application/merge-patch+json",
                          "Accept": "application/json",
                      })
    try:
        with urlopen(request, context=ca, timeout=20) as response:
            audit_id = response.headers.get("Audit-Id")
            body = json.loads(response.read())
            return response.status, audit_id, body
    except (HTTPError, URLError) as error:
        raise RuntimeError("fixture ServiceAccount PATCH request failed") from error


def event_matches_request(event, *, audit_id, action):
    ref = event.get("objectRef") or {}
    request_body = event.get("requestObject")
    return (
        event.get("auditID") == audit_id
        and event.get("stage") == "ResponseComplete"
        and event.get("level") == "Request"
        and event.get("verb") == action["verb"]
        and (event.get("user") or {}).get("username") == action["username"]
        and ref.get("namespace") == action["namespace"]
        and ref.get("resource") == action["resource"]
        and ref.get("name") == action["name"]
        and request_body == action["request_body"]
        and (event.get("responseStatus") or {}).get("code") == 200
    )


def approval_join_passes(event, approval, receipt):
    if not approval or not receipt:
        return False
    approved = approval["approved_request"]
    expected = {
        "username": approved["username"], "verb": "patch", "namespace": NAMESPACE,
        "resource": "configmaps", "name": approved["name"],
        "request_body": approved["request_body"],
    }
    return (
        approval.get("status") == "approved"
        and approved["username"] == USERNAME
        and approval.get("approved_by") == "fixture-approver@example.invalid"
        and bool(approval.get("justification"))
        and approval.get("approval_id") == receipt.get("approval_id")
        and receipt.get("audit_id") == event.get("auditID")
        and receipt.get("action_id") == approval.get("action_id")
        and event_matches_request(event, audit_id=receipt.get("audit_id"), action=expected)
    )


def record_external_receipt(approval, audit_id):
    """Fixture procedure receipt; this data is external to the native audit event."""
    return {"action_id": approval["action_id"], "approval_id": approval["approval_id"],
            "audit_id": audit_id}


def issue_scoped_token(lab, kubeconfig, destination):
    command = ["kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{CLUSTER_NAME}",
               "-n", NAMESPACE, "create", "token", SERVICE_ACCOUNT, "--duration=10m"]
    result = subprocess.run(command, text=True, capture_output=True, env=lab.env, timeout=30)
    if result.returncode or not result.stdout.strip():
        lab.block("Could not pre-issue the short-lived fixture ServiceAccount token")
    token = result.stdout.strip()
    view = subprocess.run(["kubectl", "--kubeconfig", str(kubeconfig), "--context",
                           f"kind-{CLUSTER_NAME}", "config", "view", "--raw", "--minify", "-o", "json"],
                          text=True, capture_output=True, env=lab.env, timeout=20)
    if view.returncode:
        lab.block("Could not read the fixture API endpoint and CA")
    config = json.loads(view.stdout)
    cluster = config["clusters"][0]["cluster"]
    user_config = {
        "apiVersion": "v1", "kind": "Config",
        "clusters": [{"name": "fixture", "cluster": {
            "server": cluster["server"],
            "certificate-authority-data": cluster["certificate-authority-data"],
        }}],
        "contexts": [{"name": "fixture", "context": {"cluster": "fixture", "user": "fixture"}}],
        "current-context": "fixture",
        "users": [{"name": "fixture", "user": {"token": token}}],
    }
    destination.write_text(json.dumps(user_config))
    destination.chmod(0o600)
    del token
    return view.stdout


@contextmanager
def audited_cluster(lab):
    global CLUSTER_NAME
    CLUSTER_NAME = lab.cluster + CLUSTER_SUFFIX
    with tempfile.TemporaryDirectory(prefix="saf-0606-034-") as temp:
        root = Path(temp).resolve()
        audit_dir = root / "audit"
        audit_dir.mkdir()
        kubeconfig = root / "kubeconfig"
        config = root / "kind.yaml"
        template = (HERE / "kind.yaml.in").read_text()
        policy = (HERE / "audit-policy.yaml").resolve()
        config.write_text(template.replace("@POLICY_PATH@", json.dumps(str(policy)))
                          .replace("@AUDIT_DIR@", json.dumps(str(audit_dir))))
        existing = lab.command("kind", "get", "clusters").stdout.splitlines()
        if CLUSTER_NAME in existing:
            lab.block("Case-owned audit cluster name is already in use")
        try:
            lab.command("kind", "create", "cluster", "--name", CLUSTER_NAME,
                        "--image", NODE_IMAGE, "--config", str(config),
                        "--kubeconfig", str(kubeconfig), "--wait", "90s", timeout=480)
            yield kubeconfig, audit_dir
        finally:
            lab.command("kind", "delete", "cluster", "--name", CLUSTER_NAME,
                        "--kubeconfig", str(kubeconfig), timeout=90)


def run(lab):
    fixture = fixtures()
    incidents = incident_record()
    with audited_cluster(lab) as (kubeconfig, audit_dir):
        lab.command(*kubectl_args(kubeconfig), "create", "namespace", NAMESPACE, timeout=25)
        objects = [
            {"apiVersion": "v1", "kind": "ServiceAccount",
             "metadata": {"name": SERVICE_ACCOUNT, "namespace": NAMESPACE}},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
             "metadata": {"name": "fixture-emergency-configmap-patch", "namespace": NAMESPACE},
             "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                        "resourceNames": [fixture["no_justification"]["name"],
                                          fixture["approved_action"]["name"]],
                        "verbs": ["patch"]}]},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
             "metadata": {"name": "fixture-emergency-configmap-patch", "namespace": NAMESPACE},
             "subjects": [{"kind": "ServiceAccount", "name": SERVICE_ACCOUNT, "namespace": NAMESPACE}],
             "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                         "name": "fixture-emergency-configmap-patch"}},
        ]
        for item in objects:
            admin_create(lab, kubeconfig, item)
        for name in (fixture["no_justification"]["name"],
                     fixture["approved_action"]["name"]):
            admin_create(lab, kubeconfig, {
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": name, "namespace": NAMESPACE,
                             "labels": {"saf.example/purpose": "inert-breakglass-fixture"}},
                "data": {"state": "before"},
            })

        token_path = kubeconfig.with_name("fixture-emergency.kubeconfig")
        kubeconfig_json = issue_scoped_token(lab, kubeconfig, token_path)
        server, ca = request_context(kubeconfig_json)
        token = json.loads(token_path.read_text())["users"][0]["user"]["token"]

        nojust = fixture["no_justification"]
        nojust_body = nojust["request_body"]
        nojust_status, nojust_id, nojust_response = patch_configmap(
            server, ca, token, nojust["name"], nojust_body)
        nojust_events = wait_for_audit_event(audit_dir, nojust_id)
        nojust_matches = [event for event in nojust_events if event_matches_request(
            event, audit_id=nojust_id, action={
                "username": USERNAME, "verb": "patch", "namespace": NAMESPACE,
                "resource": "configmaps", "name": nojust["name"], "request_body": nojust_body,
            })]
        nojust_approval = incidents.get("no_justification_record")
        nojust_receipt = None
        nojust_join = bool(nojust_matches) and approval_join_passes(
            nojust_matches[0], nojust_approval, nojust_receipt)
        lab.check("positive", "The pre-issued scoped ServiceAccount completes the inert no-justification PATCH",
                  nojust_status == 200 and nojust_response.get("metadata", {}).get("name") == nojust["name"],
                  {"http_status": nojust_status, "target": nojust["name"],
                   "audit_id_header_present": bool(nojust_id)})
        lab.check("red", "A native audit event exists but no-justification action has no matching approval record",
                  len(nojust_matches) == 1 and not nojust_join,
                  {"native_response_complete_matches": len(nojust_matches),
                   "independently_confirmed_audit_id": bool(nojust_id) and len(nojust_matches) == 1,
                   "external_approval_record_present": bool(nojust_approval),
                   "approval_join": nojust_join})

        approved = incidents["approved_action"]
        approved_request = approved["approved_request"]
        expected_request = {
            "username": USERNAME, "verb": "patch", "namespace": NAMESPACE,
            "resource": "configmaps", "name": fixture["approved_action"]["name"],
            "request_body": fixture["approved_action"]["request_body"],
        }
        if approved_request != expected_request:
            lab.block("The external approval fixture does not match the case-owned API request fixture")
        status, audit_id, response = patch_configmap(
            server, ca, token, approved_request["name"], approved_request["request_body"])
        events = wait_for_audit_event(audit_dir, audit_id)
        exact_events = [event for event in events if event_matches_request(
            event, audit_id=audit_id, action={
                "username": USERNAME, "verb": approved_request["verb"],
                "namespace": approved_request["namespace"], "resource": approved_request["resource"],
                "name": approved_request["name"], "request_body": approved_request["request_body"],
            })]
        # This separate fixture procedure binds the observed native audit ID to its prior approval.
        receipt = record_external_receipt(approved, audit_id)
        joined = (len(exact_events) == 1 and approval_join_passes(
            exact_events[0], approved, receipt))
        lab.check("positive", "The authorized case uses the same scoped identity for a normal ConfigMap PATCH",
                  status == 200 and response.get("metadata", {}).get("name") == approved_request["name"],
                  {"http_status": status, "target": approved_request["name"],
                   "audit_id_header_present": bool(audit_id)})
        lab.check("green", "The independent approval and execution receipt join the exact native audit event",
                  joined,
                  {"approval_id": approved["approval_id"], "action_id": approved["action_id"],
                   "native_response_complete_matches": len(exact_events),
                   "independently_confirmed_audit_id": bool(audit_id) and len(exact_events) == 1,
                   "exact_request_matches_approval": len(exact_events) == 1,
                   "approval_join": joined})
        swapped_id = record_external_receipt(approved, nojust_id)
        wrong_event_rejected = not approval_join_passes(nojust_matches[0], approved, swapped_id)
        wrong_id_rejected = not approval_join_passes(exact_events[0], approved, swapped_id)
        lab.check("positive", "The approval cannot be joined to the other real request or its audit ID",
                  wrong_event_rejected and wrong_id_rejected and audit_id != nojust_id,
                  {"wrong_request_rejected": wrong_event_rejected,
                   "wrong_audit_id_rejected": wrong_id_rejected, "distinct_ids": audit_id != nojust_id})
        (lab.evidence / "breakglass-observations.json").write_text(json.dumps({
            "namespace": NAMESPACE, "username": USERNAME,
            "no_justification": {"audit_id": nojust_id, "events": [summarize(e) for e in nojust_events],
                                 "approval_join": nojust_join},
            "approved_action": {"approval_id": approved["approval_id"], "action_id": approved["action_id"],
                                "audit_id": audit_id, "events": [summarize(e) for e in events],
                                "approval_join": joined, "execution_receipt": receipt},
            "credential_material_recorded": False,
        }, indent=2) + "\n")
        del token
