"""Exercise CRD schema/CEL, VAP, and required webhook admission independently."""
import base64
import json
from pathlib import Path
import subprocess
import tempfile
import time


HERE = Path(__file__).parent
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
AI_NAMESPACE = "saf-0605-009-ai"
OTHER_NAMESPACE = "saf-0605-009-other"
POLICY = "saf-0605-009-ai-constraints"
WEBHOOK_CONFIGURATION = "saf-0605-009-policy"
WEBHOOK_ENTRY = "saf-0605-009.example.test"
SERVICE = "saf-0605-009-webhook"
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
AUDIT_POLICY = "/etc/kubernetes/saf-0605-009-audit.yaml"
AUDIT_LOG = "/var/log/kubernetes/saf-0605-009-audit.jsonl"
WEBHOOK_LABEL = "saf-k8s.example/webhook-validation"
WEBHOOK_DENIAL = "SAF-0605-009: modelRef models/unreviewed-demo is not approved"
SCOPE = (
    "One fresh Kubernetes v1.36.1 kind cluster. A namespaced inert InferencePlan CRD stores only "
    "synthetic scalar configuration and has no controller or workload effect. The CRD structural "
    "schema and one CEL rule validate shape and a 3072 token ceiling; a namespace-scoped VAP "
    "enforces separate quota and semantic rules. A case-owned HTTPS AdmissionReview webhook "
    "then allows only the approved synthetic modelRef for explicitly labeled CRs in the selected "
    "namespace. All custom-resource probes are named server-side dry-runs. A schema-invalid "
    "dry-run is correlated to a metadata-only audit response and absence of a matching backend "
    "event. The only Pod is the owned AdmissionReview fixture; no AI operator or generated AI workload is present."
)


def prepare_kind(_lab, temporary: Path) -> Path:
    """Enable a narrow metadata-only audit trail for the malformed CR ordering probe."""
    policy = temporary / "audit-policy.yaml"
    policy.write_text(f"""apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: [RequestReceived]
rules:
- level: Metadata
  verbs: [create]
  namespaces: [{AI_NAMESPACE}]
  resources:
  - group: ai-lab.example.test
    resources: [inferenceplans]
- level: None
""", encoding="utf-8")
    config = temporary / "kind.yaml"
    config.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: {json.dumps(str(policy))}
    containerPath: {AUDIT_POLICY}
    readOnly: true
kubeadmConfigPatches:
- |
  apiVersion: kubeadm.k8s.io/v1beta4
  kind: ClusterConfiguration
  apiServer:
    extraArgs:
    - name: audit-policy-file
      value: {AUDIT_POLICY}
    - name: audit-log-path
      value: {AUDIT_LOG}
    - name: audit-log-mode
      value: blocking
    extraVolumes:
    - name: saf-0605-009-audit-policy
      hostPath: {AUDIT_POLICY}
      mountPath: {AUDIT_POLICY}
      readOnly: true
      pathType: File
    - name: saf-0605-009-audit-log
      hostPath: /var/log/kubernetes
      mountPath: /var/log/kubernetes
      pathType: DirectoryOrCreate
""", encoding="utf-8")
    return config


def _audit_rows(lab):
    result = subprocess.run(
        ["docker", "exec", f"{lab.cluster}-control-plane", "cat", AUDIT_LOG],
        capture_output=True, text=True, env=lab.env, timeout=8,
    )
    if result.returncode != 0:
        return []
    return [json.loads(row) for row in result.stdout.splitlines() if row.strip()]


def _find_audit(lab, name):
    for event in reversed(_audit_rows(lab)):
        ref = event.get("objectRef", {})
        if (event.get("stage") == "ResponseComplete" and event.get("verb") == "create"
                and ref.get("resource") == "inferenceplans"
                and ref.get("apiGroup") == "ai-lab.example.test"
                and ref.get("namespace") == AI_NAMESPACE and ref.get("name") == name
                and "dryRun=All" in event.get("requestURI", "")):
            return event
    return None


def _wait_audit(lab, name):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        event = _find_audit(lab, name)
        if event:
            return event
        time.sleep(0.3)
    lab.block(f"No matching metadata audit event for inferenceplans/{name}")


def _kubectl(lab, *args, payload=None, allow_failure=False, timeout=35):
    return lab.kubectl(*args, payload=payload, allow_failure=allow_failure, timeout=timeout)


def _fixtures():
    return json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))


def _namespace(name, enabled=False):
    labels = {"saf-k8s.example/ai-validation": "enabled"} if enabled else {}
    return {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name, "labels": labels}}


def _request(lab, namespace, obj):
    item = json.loads(json.dumps(obj))
    item["metadata"]["namespace"] = namespace
    args = ["create", "-f", "-", "-o", "json", "--dry-run=server", "--validate=false"]
    return _kubectl(lab, "-n", namespace, *args, payload=json.dumps(item), allow_failure=True)


def _require_failure(lab, phase, claim, result, fragments):
    matched = result.returncode != 0 and all(fragment in result.stderr for fragment in fragments)
    lab.check(phase, claim, matched, {
        "rejected": result.returncode != 0,
        "expected_rejection_fragments": fragments,
        "rejection_text_matched": matched,
    })


def _make_ca(lab, directory):
    key, cert = directory / "webhook-ca.key", directory / "webhook-ca.crt"
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "2",
                "-subj", "/CN=SAF-0605-009 synthetic CA",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    return key, cert


def _make_leaf(lab, directory, ca):
    key, csr, cert = directory / "webhook.key", directory / "webhook.csr", directory / "webhook.crt"
    ext = directory / "webhook.ext"
    ext.write_text(
        f"subjectAltName=DNS:{SERVICE}.{AI_NAMESPACE}.svc\n"
        "extendedKeyUsage=serverAuth\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "authorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n", encoding="ascii")
    lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={SERVICE}")
    lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca[1]),
                "-CAkey", str(ca[0]), "-CAcreateserial", "-out", str(cert), "-days", "2",
                "-extfile", str(ext))
    lab.command("openssl", "verify", "-CAfile", str(ca[1]), "-purpose", "sslserver", str(cert))
    return cert, key


def _webhook_server():
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": "saf-0605-009-webhook", "namespace": AI_NAMESPACE},
        "spec": {"replicas": 1,
                 "selector": {"matchLabels": {"app": "saf-0605-009-webhook"}},
                 "template": {
                     "metadata": {"labels": {"app": "saf-0605-009-webhook"}},
                     "spec": {"automountServiceAccountToken": False,
                              "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
                              "containers": [{
                                  "name": "webhook", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                                  "command": ["python", "/fixture.py"],
                                  "env": [{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}],
                                  "ports": [{"name": "https", "containerPort": 8443}],
                                  "readinessProbe": {"tcpSocket": {"port": 8443}, "periodSeconds": 1},
                                  "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                                "limits": {"cpu": "100m", "memory": "96Mi"}},
                                  "securityContext": {"allowPrivilegeEscalation": False,
                                                      "readOnlyRootFilesystem": True,
                                                      "runAsNonRoot": True, "runAsUser": 10001,
                                                      "capabilities": {"drop": ["ALL"]}},
                                  "volumeMounts": [
                                      {"name": "code", "mountPath": "/fixture.py", "subPath": "fixture.py", "readOnly": True},
                                      {"name": "tls", "mountPath": "/tls", "readOnly": True},
                                  ],
                              }],
                              "volumes": [
                                  {"name": "code", "configMap": {"name": "saf-0605-009-code"}},
                                  {"name": "tls", "secret": {"secretName": "saf-0605-009-tls"}},
                              ]},
                 }},
    }


def _webhook_config(ca_bundle):
    return {
        "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingWebhookConfiguration",
        "metadata": {"name": WEBHOOK_CONFIGURATION},
        "webhooks": [{
            "name": WEBHOOK_ENTRY, "admissionReviewVersions": ["v1"],
            "sideEffects": "None", "failurePolicy": "Fail", "matchPolicy": "Equivalent",
            "timeoutSeconds": 3,
            "clientConfig": {"service": {"namespace": AI_NAMESPACE, "name": SERVICE,
                                          "path": "/validate", "port": 443}, "caBundle": ca_bundle},
            "namespaceSelector": {"matchLabels": {"saf-k8s.example/ai-validation": "enabled"}},
            "objectSelector": {"matchLabels": {WEBHOOK_LABEL: "enabled"}},
            "rules": [{"apiGroups": ["ai-lab.example.test"], "apiVersions": ["v1"],
                       "operations": ["CREATE"], "resources": ["inferenceplans"],
                       "scope": "Namespaced"}],
        }],
    }


def _backend_events(lab):
    result = _kubectl(lab, "-n", AI_NAMESPACE, "logs", "deployment/saf-0605-009-webhook",
                      "--tail=100", allow_failure=True)
    rows = []
    for line in result.stdout.splitlines():
        if line.startswith("{"):
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _wait_backend(lab, name, allowed, *, status_code=None, reason=None, message=None):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if any(row.get("event") == "admission" and row.get("probe") == name
               and row.get("allowed") is allowed and row.get("response_code") == status_code
               and row.get("response_reason") == reason and row.get("response_message") == message
               for row in _backend_events(lab)):
            return True
        time.sleep(0.3)
    return False


def _install_webhook(lab, directory):
    ca = _make_ca(lab, directory)
    cert, key = _make_leaf(lab, directory, ca)
    _kubectl(lab, "-n", AI_NAMESPACE, "create", "secret", "tls", "saf-0605-009-tls",
             "--cert", str(cert), "--key", str(key))
    code = {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "saf-0605-009-code", "namespace": AI_NAMESPACE},
            "data": {"fixture.py": (HERE / "fixture.py").read_text(encoding="utf-8")}}
    _kubectl(lab, "-n", AI_NAMESPACE, "apply", "-f", "-", payload=json.dumps({
        "apiVersion": "v1", "kind": "List", "items": [code, _webhook_server()]}))
    service = {"apiVersion": "v1", "kind": "Service",
               "metadata": {"name": SERVICE, "namespace": AI_NAMESPACE},
               "spec": {"selector": {"app": "saf-0605-009-webhook"},
                        "ports": [{"name": "https", "port": 443, "targetPort": 8443}]}}
    _kubectl(lab, "-n", AI_NAMESPACE, "create", "-f", "-", payload=json.dumps(service))
    _kubectl(lab, "-n", AI_NAMESPACE, "rollout", "status",
             "deployment/saf-0605-009-webhook", "--timeout=90s", timeout=100)
    deadline = time.monotonic() + 20
    ready = []
    while time.monotonic() < deadline:
        endpoints = json.loads(_kubectl(lab, "-n", AI_NAMESPACE, "get", "endpointslices",
                                        "-l", "kubernetes.io/service-name=" + SERVICE, "-o", "json").stdout)
        ready = [endpoint for slice_obj in endpoints.get("items", [])
                 for endpoint in slice_obj.get("endpoints", [])
                 if endpoint.get("conditions", {}).get("ready") is True]
        if len(ready) == 1:
            break
        time.sleep(0.3)
    lab.check("positive", "Owned webhook backend has a ready Service endpoint",
              len(ready) == 1, {"ready_endpoints": len(ready)})
    bundle = base64.b64encode(ca[1].read_bytes()).decode("ascii")
    _kubectl(lab, "apply", "-f", "-", payload=json.dumps(_webhook_config(bundle)))


def run(lab):
    version = json.loads(lab.kubectl("get", "--raw=/version").stdout)
    lab.check("positive", "Disposable API server is Kubernetes v1.36.1",
              version.get("gitVersion") == "v1.36.1", {"server": version.get("gitVersion")})
    lab.kubectl("create", "-f", str(HERE / "crd.yaml"))
    lab.kubectl("wait", "--for=condition=Established", "crd/inferenceplans.ai-lab.example.test", "--timeout=30s")
    ai = _fixtures()
    lab.create(_namespace(AI_NAMESPACE, enabled=True))
    lab.create(_namespace(OTHER_NAMESPACE))
    before_webhook = _request(lab, AI_NAMESPACE, ai["webhook_disallowed"])
    lab.check("red", "Same schema-valid unapproved object is admitted before webhook registration",
              before_webhook.returncode == 0, {"admitted_without_webhook": before_webhook.returncode == 0})
    with tempfile.TemporaryDirectory(prefix="saf-0605-009-") as temp:
        _install_webhook(lab, Path(temp))

    approved = ai["webhook_approved"]
    deadline = time.monotonic() + 20
    while True:
        allowed = _request(lab, AI_NAMESPACE, approved)
        allowed_seen = any(row.get("probe") == approved["metadata"]["name"]
                           and row.get("allowed") is True for row in _backend_events(lab))
        if (allowed.returncode == 0 and allowed_seen) or time.monotonic() >= deadline:
            break
        time.sleep(0.3)
    lab.check("positive", "The approved comparison reaches the registered webhook and is admitted",
              allowed.returncode == 0 and allowed_seen,
              {"api_admitted": allowed.returncode == 0, "backend_recorded_allow": allowed_seen})

    # Schema-invalid but webhook-selected metadata makes source ordering observable.
    missing = ai["malformed_missing_model"]
    malformed = _request(lab, AI_NAMESPACE, missing)
    audit = _wait_audit(lab, missing["metadata"]["name"])
    no_call = not any(row.get("event") == "admission"
                      and row.get("probe") == missing["metadata"]["name"]
                      for row in _backend_events(lab))
    schema_status = (audit.get("responseStatus", {}).get("code") == 422
                     and audit.get("responseStatus", {}).get("reason") == "Invalid"
                     and "spec.modelRef" in audit.get("responseStatus", {}).get("message", "")
                     and "Required value" in audit.get("responseStatus", {}).get("message", ""))
    stderr_schema = ("spec.modelRef" in malformed.stderr and "Required value" in malformed.stderr)
    lab.check("green", "Malformed structural CR is rejected before matching webhook admission",
              malformed.returncode != 0 and stderr_schema and schema_status and no_call
              and "requestObject" not in audit and bool(audit.get("auditID")),
              {"api_status_code": audit.get("responseStatus", {}).get("code"),
               "api_status_reason": audit.get("responseStatus", {}).get("reason"),
               "api_status_message": audit.get("responseStatus", {}).get("message"),
               "required_field_message": schema_status, "matching_backend_call_absent": no_call,
               "kubectl_schema_message_matched": stderr_schema,
               "metadata_only_audit": "requestObject" not in audit,
               "audit_id_present": bool(audit.get("auditID"))})

    # This identical VAP quota counterfactual passes before binding.
    before = _request(lab, AI_NAMESPACE, ai["quota_counterfactual"])
    lab.check("red", "Quota-invalid but schema-valid object is admitted before VAP binding",
              before.returncode == 0, {"admitted_before_binding": before.returncode == 0,
                                       "server_side_dry_run": True})
    lab.kubectl("create", "-f", str(HERE / "policy.yaml"))
    lab.kubectl("create", "-f", str(HERE / "binding.yaml"))
    deadline = time.monotonic() + 20
    while True:
        after = _request(lab, AI_NAMESPACE, ai["quota_counterfactual"])
        if (after.returncode != 0 and POLICY in after.stderr) or time.monotonic() >= deadline:
            break
        time.sleep(0.3)
    quota_status = _wait_audit(lab, ai["quota_counterfactual"]["metadata"]["name"])["responseStatus"]
    quota_denied = (quota_status.get("code") == 422 and quota_status.get("reason") == "Invalid"
                    and POLICY in quota_status.get("message", "")
                    and "replica-times-GPU quota exceeds 4" in quota_status.get("message", ""))
    lab.check("green", "Same quota counterfactual is denied in selected AI namespace",
              after.returncode != 0 and quota_denied,
              {"policy_denied_request": quota_denied, "api_status_code": quota_status.get("code")})
    outside = _request(lab, OTHER_NAMESPACE, ai["quota_counterfactual"])
    lab.check("positive", "Same quota-invalid object remains outside VAP namespace scope",
              outside.returncode == 0, {"admitted_outside_scope": outside.returncode == 0,
                                        "server_side_dry_run": True})
    over_field = ai["schema_gpu_above_max"]
    field_result = _request(lab, AI_NAMESPACE, over_field)
    _require_failure(lab, "green", "Structural schema rejects gpu above hard maximum",
                     field_result, ["spec.gpu", "should be less than or equal to 2"])
    over_cel = ai["cel_tokens_above_limit"]
    over_cel["metadata"]["labels"] = {WEBHOOK_LABEL: "enabled"}
    cel_result = _request(lab, AI_NAMESPACE, over_cel)
    cel_audit = _wait_audit(lab, over_cel["metadata"]["name"])
    cel_status = cel_audit.get("responseStatus", {})
    cel_invalid = (cel_status.get("code") == 422 and cel_status.get("reason") == "Invalid"
                   and "CEL inference maxTokens must not exceed 3072" in cel_status.get("message", ""))
    cel_no_call = not any(row.get("probe") == over_cel["metadata"]["name"]
                          for row in _backend_events(lab))
    lab.check("green", "Native CRD CEL rejects the selected request before webhook evaluation",
              cel_result.returncode != 0 and cel_invalid and cel_no_call,
              {"native_cel_invalid": cel_invalid, "matching_backend_call_absent": cel_no_call})

    denied = _request(lab, AI_NAMESPACE, ai["webhook_disallowed"])
    denied_seen = _wait_backend(
        lab, ai["webhook_disallowed"]["metadata"]["name"], False,
        status_code=403, reason="Forbidden", message=WEBHOOK_DENIAL)
    denied_audit = _wait_audit(lab, ai["webhook_disallowed"]["metadata"]["name"])
    exact_denial = (denied.returncode != 0 and "(Forbidden)" in denied.stderr
                    and WEBHOOK_ENTRY in denied.stderr and WEBHOOK_DENIAL in denied.stderr
                    and denied_audit.get("responseStatus", {}).get("code") == 403
                    and denied_audit.get("responseStatus", {}).get("reason") == "Forbidden"
                    and WEBHOOK_DENIAL in denied_audit.get("responseStatus", {}).get("message", ""))
    lab.check("green", "Webhook denies valid-schema disallowed modelRef with exact response",
              exact_denial and denied_seen,
              {"exact_api_denial": exact_denial, "backend_recorded_denial": denied_seen,
               "api_status_code": denied_audit.get("responseStatus", {}).get("code"),
               "api_status_reason": denied_audit.get("responseStatus", {}).get("reason"),
               "api_status_message": denied_audit.get("responseStatus", {}).get("message"),
               "expected_status_code": 403, "expected_message": WEBHOOK_DENIAL,
               "dry_run_only": True})
    unselected = _request(lab, OTHER_NAMESPACE, ai["webhook_disallowed"])
    lab.check("positive", "Webhook selector leaves the same synthetic object outside namespace scope",
              unselected.returncode == 0,
              {"admitted_outside_scope": unselected.returncode == 0,
               "server_side_dry_run": True})
