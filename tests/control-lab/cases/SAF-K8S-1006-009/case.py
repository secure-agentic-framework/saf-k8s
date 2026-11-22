"""Collect independent policy, API audit, and policy-history evidence."""
from hashlib import sha256
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
KYVERNO_VERSION = "v1.20.0"
CHART_VERSION = "3.10.0"
CHART_SHA256 = "55961392dc0821eb367323f0e9585c061dd4407ef7ada921bd56ea1642c2a301"
NAMESPACE = "saf-1006-009"
KYVERNO_NAMESPACE = "kyverno"
POLICY = "saf-1006-009-evidence"
AUDIT_CONFIG = "/etc/kubernetes/saf-1006-009-audit.yaml"
AUDIT_LOG = "/var/log/kubernetes/saf-1006-009/audit.jsonl"
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
MESSAGE = "SAF-K8S-1006-009: fixture evidence must be present"
SCOPE = (
    "One fresh Kubernetes v1.36.1 Kind cluster and Kyverno v1.20.0 from chart 3.10.0. "
    "One owned namespace contains only inert ConfigMaps. A namespaced Kyverno policy "
    "moves from Audit r1 to Deny r2. The case separately checks PolicyReport state, "
    "native API audit records for exact allowed and denied requests, two source-control "
    "policy revisions, and a filtered evidence export to a scoped in-cluster receiver. "
    "This is fixture evidence for one cluster and policy path, not production retention, "
    "SIEM/GRC acceptance, or AI workload coverage."
)


def prepare_kind(_lab, temporary: Path) -> Path:
    """Enable request/response audit for synthetic ConfigMap CREATEs in this namespace."""
    policy = temporary / "saf-1006-009-audit.yaml"
    policy.write_text(f"""apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: [RequestReceived]
rules:
- level: RequestResponse
  verbs: [create]
  namespaces: [{NAMESPACE}]
  resources:
  - group: ""
    resources: [configmaps]
- level: None
""", encoding="utf-8")
    log_dir = temporary / "audit"
    log_dir.mkdir()
    (log_dir / "audit.jsonl").touch()
    config = temporary / "kind.yaml"
    config.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: {json.dumps(str(policy))}
    containerPath: {AUDIT_CONFIG}
    readOnly: true
  - hostPath: {json.dumps(str(log_dir))}
    containerPath: /var/log/kubernetes/saf-1006-009
kubeadmConfigPatches:
- |
  apiVersion: kubeadm.k8s.io/v1beta4
  kind: ClusterConfiguration
  apiServer:
    extraArgs:
    - name: audit-policy-file
      value: {AUDIT_CONFIG}
    - name: audit-log-path
      value: {AUDIT_LOG}
    - name: audit-log-mode
      value: blocking
    extraVolumes:
    - name: saf-1006-009-audit-policy
      hostPath: {AUDIT_CONFIG}
      mountPath: {AUDIT_CONFIG}
      readOnly: true
      pathType: File
    - name: saf-1006-009-audit-log
      hostPath: /var/log/kubernetes/saf-1006-009
      mountPath: /var/log/kubernetes/saf-1006-009
      pathType: DirectoryOrCreate
""", encoding="utf-8")
    return config


def _kubectl(lab, *args, payload=None, allow_failure=False, timeout=40):
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
               f"kind-{lab.cluster}", f"--request-timeout={max(5, timeout - 5)}s", *args]
    return lab.command(*command, payload=payload, allow_failure=allow_failure, timeout=timeout)


def _helm(lab, *args, timeout=220):
    home = Path(lab.kubeconfig).parent / "helm-1006-009"
    home.mkdir(exist_ok=True)
    return lab.command("env", f"HELM_CACHE_HOME={home / 'cache'}",
                       f"HELM_CONFIG_HOME={home / 'config'}",
                       f"HELM_REGISTRY_CONFIG={home / 'registry.json'}",
                       f"HELM_DATA_HOME={home / 'data'}", "helm", *args, timeout=timeout)


def _install_kyverno(lab):
    directory = Path(lab.kubeconfig).parent
    _helm(lab, "pull", "oci://ghcr.io/kyverno/charts/kyverno", "--version", CHART_VERSION,
          "--destination", str(directory), timeout=100)
    chart = directory / f"kyverno-{CHART_VERSION}.tgz"
    if sha256(chart.read_bytes()).hexdigest() != CHART_SHA256:
        lab.block("Pinned Kyverno chart archive failed the SHA-256 check")
    _helm(lab, "upgrade", "--install", "kyverno", str(chart),
          "--kubeconfig", str(lab.kubeconfig), "--kube-context", f"kind-{lab.cluster}",
          "--namespace", KYVERNO_NAMESPACE, "--create-namespace", "--wait", "--timeout", "180s",
          "--set", "webhooksCleanup.enabled=false",
          "--set", "features.generateValidatingAdmissionPolicy.enabled=false")
    _kubectl(lab, "-n", KYVERNO_NAMESPACE, "rollout", "status",
             "deployment/kyverno-admission-controller", "--timeout=150s", timeout=160)


def _fixtures():
    return json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))


def _policy_ready(lab):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        result = _kubectl(lab, "-n", NAMESPACE, "get", "namespacedvalidatingpolicy", POLICY,
                          "-o", "json", allow_failure=True)
        if result.returncode == 0:
            ready = json.loads(result.stdout).get("status", {}).get("conditionStatus", {}).get("ready")
            if ready is True:
                return
        time.sleep(0.5)
    lab.block("Kyverno policy did not become Ready")


def _apply_policy(lab, source, revision, action):
    applied = _kubectl(lab, "-n", NAMESPACE, "apply", "-f", "-", "-o", "json", payload=source)
    policy = json.loads(applied.stdout)
    if (policy["metadata"]["labels"]["saf-lab.example/policy-revision"] != revision
            or policy["spec"].get("validationActions") != [action]):
        lab.block(f"API response did not identify the expected fixture policy {revision}")
    _policy_ready(lab)


def _submit(lab, obj):
    return _kubectl(lab, "-n", NAMESPACE, "create", "-f", "-", "-o", "json",
                    payload=json.dumps(obj), allow_failure=True, timeout=30)


def _report_row(lab, resource_name, result, message=None):
    response = _kubectl(lab, "-n", NAMESPACE, "get", "policyreports.wgpolicyk8s.io",
                        "-o", "json", allow_failure=True)
    if response.returncode:
        return None
    for report in json.loads(response.stdout).get("items", []):
        scope = report.get("scope") or {}
        if (scope.get("kind") != "ConfigMap" or scope.get("namespace") != NAMESPACE
                or scope.get("name") != resource_name):
            continue
        for row in report.get("results", []):
            if (row.get("policy") == f"{NAMESPACE}/{POLICY}" and row.get("result") == result
                    and row.get("source") == "KyvernoValidatingPolicy"
                    and (message is None or row.get("message") == message)):
                return row
    return None


def _wait_report(lab, name, result, message=None):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        row = _report_row(lab, name, result, message)
        if row:
            return row
        time.sleep(0.5)
    return None


def _audit_events(lab):
    result = lab.command("docker", "exec", f"{lab.cluster}-control-plane", "cat", AUDIT_LOG,
                         allow_failure=True, timeout=15)
    events = []
    if result.returncode:
        return events
    for line in result.stdout.splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def _audit_for_marker(lab, obj):
    name = obj["metadata"]["name"]
    marker = obj["metadata"]["labels"]["saf-lab.example/request-marker"]
    revision = obj["metadata"]["labels"]["saf-lab.example/policy-revision"]
    found = []
    for event in _audit_events(lab):
        ref = event.get("objectRef") or {}
        request = event.get("requestObject") or {}
        meta = request.get("metadata") or {}
        labels = meta.get("labels") or {}
        if (event.get("stage") == "ResponseComplete" and event.get("verb") == "create"
                and ref.get("resource") == "configmaps" and ref.get("namespace") == NAMESPACE
                and ref.get("name") == name and labels.get("saf-lab.example/request-marker") == marker
                and labels.get("saf-lab.example/policy-revision") == revision
                and meta.get("annotations", {}).get("saf-lab.example/policy-revision") == revision):
            found.append(event)
    return found


def _git_history(lab):
    """Create deterministic local commits for the two policy fixture revisions."""
    root = Path(lab.kubeconfig).parent / "policy-history-1006-009"
    lab.command("git", "init", "--template=", "--object-format=sha1", "-b", "main", str(root))
    commits = {}
    sources = {}
    for day, (revision, filename) in enumerate((("r1", "policy-audit.yaml"), ("r2", "policy-deny.yaml")), 1):
        source = (HERE / filename).read_bytes()
        (root / "policy.yaml").write_bytes(source)
        lab.command("git", "-C", str(root), "-c", "core.autocrlf=false", "add", "--", "policy.yaml")
        timestamp = f"2026-01-0{day}T00:00:00Z"
        lab.command("env", f"GIT_AUTHOR_DATE={timestamp}", f"GIT_COMMITTER_DATE={timestamp}",
                    "git", "-C", str(root), "-c", "user.name=SAF fixture",
                    "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null",
                    "-c", "commit.gpgsign=false", "commit", "-m", revision)
        oid = lab.command("git", "-C", str(root), "rev-parse", "HEAD").stdout.strip()
        committed = lab.command("git", "-C", str(root), "show", f"{oid}:policy.yaml").stdout
        if committed.encode() != source:
            lab.block(f"Committed policy bytes differ from {filename}")
        sources[revision] = committed
        commits[revision] = {"commit": oid, "policy_sha256": sha256(source).hexdigest()}
    return commits, sources


def _receiver_manifest():
    server = """from http.server import BaseHTTPRequestHandler,HTTPServer
from pathlib import Path
class H(BaseHTTPRequestHandler):
 def do_POST(self):
  n=int(self.headers.get('Content-Length','0')); b=self.rfile.read(n)
  if self.path!='/ingest' or not Path('/data/accepting').exists():
   self.send_response(503); self.end_headers(); return
  Path('/data/export.jsonl').open('ab').write(b+b'\\n')
  self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
 def log_message(self,*a): pass
HTTPServer(('0.0.0.0',8080),H).serve_forever()
"""
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "saf-1006-009-receiver", "namespace": NAMESPACE,
                     "labels": {"app": "saf-1006-009-receiver"}},
        "spec": {"automountServiceAccountToken": False,
                 "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "fsGroup": 10001,
                                     "seccompProfile": {"type": "RuntimeDefault"}},
                 "containers": [{"name": "receiver", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                                 "command": ["python", "-u", "-c", server],
                                 "ports": [{"containerPort": 8080}],
                                 "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                               "limits": {"cpu": "100m", "memory": "64Mi"}},
                                 "securityContext": {"allowPrivilegeEscalation": False,
                                                     "readOnlyRootFilesystem": True,
                                                     "capabilities": {"drop": ["ALL"]}},
                                 "volumeMounts": [{"name": "data", "mountPath": "/data"}]}],
                 "volumes": [{"name": "data", "emptyDir": {"sizeLimit": "4Mi"}}]},
    }


def _service_manifest():
    return {"apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "saf-1006-009-receiver", "namespace": NAMESPACE},
            "spec": {"selector": {"app": "saf-1006-009-receiver"},
                     "ports": [{"port": 8080, "targetPort": 8080}]}}


def _sender_manifest():
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "saf-1006-009-exporter", "namespace": NAMESPACE},
            "spec": {"automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "exporter", "image": IMAGE,
                                     "imagePullPolicy": "IfNotPresent",
                                     "command": ["python", "-c", "import time; time.sleep(3600)"],
                                     "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                                   "limits": {"cpu": "50m", "memory": "32Mi"}},
                                     "securityContext": {"allowPrivilegeEscalation": False,
                                                         "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}}}]}}


def _post(lab, body):
    code = "import sys,urllib.request; d=sys.stdin.buffer.read(); r=urllib.request.Request('http://saf-1006-009-receiver:8080/ingest',data=d,headers={'Content-Type':'application/json'},method='POST'); print(urllib.request.urlopen(r,timeout=5).status)"
    return _kubectl(lab, "-n", NAMESPACE, "exec", "-i", "saf-1006-009-exporter", "--", "python", "-c", code,
                    payload=json.dumps(body), allow_failure=True, timeout=15)


def run(lab):
    fixtures = _fixtures()
    version = json.loads(_kubectl(lab, "get", "--raw=/version").stdout)
    lab.check("positive", "API server is the pinned Kubernetes v1.36.1 release",
              version.get("gitVersion") == "v1.36.1", {"gitVersion": version.get("gitVersion")})
    _install_kyverno(lab)
    pods = json.loads(_kubectl(lab, "-n", KYVERNO_NAMESPACE, "get", "pods", "-o", "json").stdout)["items"]
    images = sorted({c["image"] for p in pods for c in p["spec"].get("containers", [])})
    expected = {f"reg.kyverno.io/kyverno/{name}:{KYVERNO_VERSION}"
                for name in ("kyverno", "background-controller", "cleanup-controller", "reports-controller")}
    lab.check("positive", "Kyverno controllers use the cataloged v1.20.0 pin",
              expected.issubset(images), {"expected": sorted(expected), "observed": images})
    _kubectl(lab, "create", "namespace", NAMESPACE)
    history, sources = _git_history(lab)
    _apply_policy(lab, sources["r1"], "r1", "Audit")
    lab.check("positive", "Policy r1 and r2 are separate source-control revisions with content hashes",
              history["r1"]["commit"] != history["r2"]["commit"]
              and history["r1"]["policy_sha256"] != history["r2"]["policy_sha256"], history)

    allowed = _submit(lab, fixtures["compliant"])
    allowed_audit = _audit_for_marker(lab, fixtures["compliant"])
    allowed_ok = (allowed.returncode == 0 and len(allowed_audit) == 1
                  and allowed_audit[0].get("responseStatus", {}).get("code") == 201)
    lab.check("green", "Native API audit records the exact allowed r1 request and revision",
              allowed_ok, {"admitted": allowed.returncode == 0,
                           "matching_audit_events": len(allowed_audit),
                           "response_code": allowed_audit[0].get("responseStatus", {}).get("code") if allowed_audit else None,
                           "request_marker": "allow-r1", "policy_revision": "r1"})

    violation = _submit(lab, fixtures["audit_violation"])
    report = _wait_report(lab, fixtures["audit_violation"]["metadata"]["name"], "fail", MESSAGE)
    row = _wait_report(lab, fixtures["compliant"]["metadata"]["name"], "pass")
    violation_audit = _audit_for_marker(lab, fixtures["audit_violation"])
    audit_ok = (violation.returncode == 0 and len(violation_audit) == 1
                and violation_audit[0].get("responseStatus", {}).get("code") == 201)
    lab.check("green", "Audit mode admits the exact r1 violation and PolicyReport records fail",
              violation.returncode == 0 and report is not None and row is not None and audit_ok,
              {"admitted": violation.returncode == 0,
               "policy_report_status": report.get("result") if report else None,
               "policy_report_source": report.get("source") if report else None,
               "allow_report_present": row is not None,
               "audit_response_code": violation_audit[0].get("responseStatus", {}).get("code") if violation_audit else None,
               "request_marker": "audit-r1", "policy_revision": "r1"})
    # Snapshot reports now: PolicyReports represent current resources, not immutable history.
    report_snapshot = {"violation": report, "compliant": row}

    _apply_policy(lab, sources["r2"], "r2", "Deny")
    pending = {**fixtures["deny_violation"], "metadata": {
        **fixtures["deny_violation"]["metadata"], "name": "saf-1006-009-policy-readiness",
    }}
    deadline = time.monotonic() + 35
    while True:
        probe = _kubectl(lab, "-n", NAMESPACE, "create", "-f", "-", "--dry-run=server",
                         payload=json.dumps(pending), allow_failure=True)
        if MESSAGE in probe.stderr or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    denied = _submit(lab, fixtures["deny_violation"])
    denied_audit = _audit_for_marker(lab, fixtures["deny_violation"])
    deny_ok = (denied.returncode != 0 and MESSAGE in denied.stderr and len(denied_audit) == 1
               and denied_audit[0].get("responseStatus", {}).get("code", 0) >= 400)
    lab.check("green", "Deny r2 refuses the same policy violation and native audit records the exact request",
              deny_ok, {"denied": denied.returncode != 0, "message_matched": MESSAGE in denied.stderr,
                        "matching_audit_events": len(denied_audit),
                        "response_code": denied_audit[0].get("responseStatus", {}).get("code") if denied_audit else None,
                        "request_marker": "deny-r2", "policy_revision": "r2"})
    regression = _submit(lab, fixtures["positive_regression"])
    regression_audit = _audit_for_marker(lab, fixtures["positive_regression"])
    positive = (regression.returncode == 0 and len(regression_audit) == 1
                and regression_audit[0].get("responseStatus", {}).get("code") == 201)
    lab.check("positive", "Compliant r2 request remains admitted with matching audit evidence",
              positive, {"admitted": regression.returncode == 0, "matching_audit_events": len(regression_audit),
                         "response_code": regression_audit[0].get("responseStatus", {}).get("code") if regression_audit else None,
                         "request_marker": "allow-r2", "policy_revision": "r2"})

    export_body = {
        "case": "SAF-K8S-1006-009", "namespace": NAMESPACE,
        "policy": POLICY, "policy_history": history,
        "policy_report_snapshot_r1": report_snapshot,
        "admission_events": {
            "allow_r1": allowed_audit[0] if allowed_audit else None,
            "audit_violation_r1": violation_audit[0] if violation_audit else None,
            "deny_r2": denied_audit[0] if denied_audit else None,
            "allow_r2": regression_audit[0] if regression_audit else None,
        },
    }
    # Receiver rejects ingestion until explicitly enabled. This is the export-loss control.
    _kubectl(lab, "create", "-f", "-", payload=json.dumps(_receiver_manifest()))
    _kubectl(lab, "create", "-f", "-", payload=json.dumps(_service_manifest()))
    _kubectl(lab, "create", "-f", "-", payload=json.dumps(_sender_manifest()))
    _kubectl(lab, "-n", NAMESPACE, "wait", "--for=condition=Ready", "pod/saf-1006-009-receiver", "--timeout=60s")
    _kubectl(lab, "-n", NAMESPACE, "wait", "--for=condition=Ready", "pod/saf-1006-009-exporter", "--timeout=60s")
    missing = _post(lab, export_body)
    no_ingest = missing.returncode != 0 and "HTTP Error 503" in missing.stderr
    untouched = _kubectl(lab, "-n", NAMESPACE, "exec", "saf-1006-009-receiver", "--",
                         "python", "-c", "from pathlib import Path; assert not Path('/data/export.jsonl').exists()",
                         allow_failure=True).returncode == 0
    lab.check("red", "Disabled scoped receiver rejects export and retains no evidence",
              no_ingest and untouched, {"post_rejected": no_ingest, "storage_absent": untouched})
    _kubectl(lab, "-n", NAMESPACE, "exec", "saf-1006-009-receiver", "--", "python", "-c",
             "from pathlib import Path; Path('/data/accepting').touch()")
    exported = _post(lab, export_body)
    received = _kubectl(lab, "-n", NAMESPACE, "exec", "saf-1006-009-receiver", "--", "cat", "/data/export.jsonl").stdout
    stored = json.loads(received.splitlines()[-1]) if received.splitlines() else {}
    http_accepted = exported.returncode == 0 and exported.stdout.strip() == "200"
    export_ok = len(received.splitlines()) == 1 and stored == export_body
    (lab.evidence / "evidence-envelope.json").write_text(json.dumps(stored, indent=2) + "\n")
    lab.check("green", "Scoped in-cluster receiver stores the correlated reports, audit events, and history",
              http_accepted and export_ok,
              {"http_200": http_accepted, "exact_envelope_retained_once": export_ok,
               "retained_admission_decisions": len(stored.get("admission_events", {}))})
