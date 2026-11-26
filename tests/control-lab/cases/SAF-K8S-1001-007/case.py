"""Compare a live synthetic workload with the kind API server's audit stream."""

import json
from pathlib import Path
import re
import subprocess
import time


CASE_DIR = Path(__file__).resolve().parent
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
WORKLOAD_IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
NAMESPACE = "saf-test"
FIXTURE_NAME = "telemetry-fixture"
AUDIT_ORACLE = "telemetry-api-oracle"
AUDIT_DIR = "/var/log/kubernetes/audit"
AUDIT_PATH = f"{AUDIT_DIR}/audit.log"
SCOPE = (
    "Kubernetes Metadata audit versus scoped telemetry for synthetic HTTP workloads in two pods "
    "on one local kind node, plus one isolated pinned-Istio synthetic access-log request. The case "
    "uses fictional model information, an inert prompt marker, and a pod-local collector. It does "
    "not establish GPU process accounting, production mesh rollout, forwarding, alerting, or retention."
)


def prepare_kind(_lab, temporary: Path) -> Path:
    policy = (CASE_DIR / "audit-policy.yaml").resolve()
    config = temporary / "kind-config.yaml"
    config.write_text(
        "kind: Cluster\n"
        "apiVersion: kind.x-k8s.io/v1alpha4\n"
        "nodes:\n  - role: control-plane\n    extraMounts:\n"
        f"      - hostPath: {json.dumps(str(policy))}\n"
        "        containerPath: /etc/kubernetes/audit-policy.yaml\n"
        "        readOnly: true\n"
        "kubeadmConfigPatches:\n  - |\n"
        "    apiVersion: kubeadm.k8s.io/v1beta4\n"
        "    kind: ClusterConfiguration\n"
        "    apiServer:\n      extraArgs:\n"
        "        - name: audit-policy-file\n"
        "          value: /etc/kubernetes/audit-policy.yaml\n"
        f"        - name: audit-log-path\n          value: {AUDIT_PATH}\n"
        "        - name: audit-log-maxage\n          value: \"1\"\n"
        "        - name: audit-log-maxbackup\n          value: \"1\"\n"
        "        - name: audit-log-maxsize\n          value: \"10\"\n"
        "      extraVolumes:\n"
        "        - name: audit-policy\n"
        "          hostPath: /etc/kubernetes/audit-policy.yaml\n"
        "          mountPath: /etc/kubernetes/audit-policy.yaml\n"
        "          readOnly: true\n          pathType: File\n"
        "        - name: audit-log\n"
        f"          hostPath: {AUDIT_DIR}\n"
        f"          mountPath: {AUDIT_DIR}\n"
        "          readOnly: false\n          pathType: DirectoryOrCreate\n",
        encoding="utf-8",
    )
    return config


def run_workload(lab, phase):
    name = f"telemetry-{phase}"
    lab.create({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name},
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 10001,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [{
                "name": "workload",
                "image": WORKLOAD_IMAGE,
                "command": ["python", "-B", "/fixture/workload.py", phase],
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]},
                },
                "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
            }],
            "volumes": [{"name": "fixture", "configMap": {"name": FIXTURE_NAME}}],
        },
    })
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{name}",
                "--timeout=110s", timeout=119)
    observed = json.loads(lab.kubectl("logs", f"pod/{name}").stdout)
    event_id = observed.pop("event_id")
    if not re.fullmatch(r"saf-k8s-1001-007-[0-9a-f]{32}", event_id):
        lab.block("The workload did not return a generated event identifier")
    return event_id, observed


def read_audit(lab):
    node = f"{lab.cluster}-control-plane"
    result = subprocess.run(
        ["docker", "exec", node, "cat", AUDIT_PATH],
        env=lab.env, capture_output=True, text=True, timeout=8,
    )
    if result.returncode:
        lab.block("The owned control plane did not expose its fixture audit file")
    # Keep audit events in memory. The runner receipt includes only scoped observations.
    return result.stdout


def read_positive(lab):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        audit = read_audit(lab)
        for line in audit.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            ref = event.get("objectRef") or {}
            if (event.get("stage") == "ResponseComplete" and event.get("verb") == "get"
                    and ref.get("resource") == "configmaps" and ref.get("name") == AUDIT_ORACLE
                    and ref.get("namespace") == NAMESPACE):
                return audit, event
        time.sleep(0.2)
    lab.block("The known Kubernetes API request was absent from the audit stream")


def _run_local_telemetry(lab):
    lab.kubectl(
        "create", "configmap", FIXTURE_NAME,
        f"--from-file={CASE_DIR / 'synthetic_services.py'}",
        f"--from-file={CASE_DIR / 'workload.py'}",
    )
    red_id, red = run_workload(lab, "red")
    green_id, green = run_workload(lab, "green")

    lab.kubectl("create", "configmap", AUDIT_ORACLE, "--from-literal=fixture=telemetry")
    lab.kubectl("get", "configmap", AUDIT_ORACLE, "-o", "name")
    audit, api = read_positive(lab)
    positive = {
        "metadata_level": api.get("level") == "Metadata",
        "completed_successfully": (api.get("responseStatus") or {}).get("code") == 200,
        "request_body_absent": "requestObject" not in api,
        "response_body_absent": "responseObject" not in api,
    }
    lab.check("positive", "The successful fixture ConfigMap read appears in the real Metadata audit file",
              all(positive.values()), positive)

    red["runtime_event_absent_from_api_audit"] = red_id not in audit
    lab.check("red", "Without supplemental collection, the workload accepts a request with no collected event",
              red == {
                  "status": 200,
                  "response_matches_event": True,
                  "records": 0,
                  "runtime_event_absent_from_api_audit": True,
              }, red)

    green["runtime_event_absent_from_api_audit"] = green_id not in audit
    lab.check("green", "Supplemental collection persists one allowlisted event while API audit omits it",
              green == {
                  "status": 200,
                  "response_matches_event": True,
                  "records": 1,
                  "persisted_event_matches_allowlist": True,
                  "prompt_absent_from_record": True,
                  "runtime_event_absent_from_api_audit": True,
              }, green)

# Additive mesh metadata check. Kept in a separate namespace so the original
# short-lived app telemetry Pods retain their existing lifecycle and results.
MESH_NAMESPACE = "saf-mesh-1001-007"
MESH_SERVER = "mesh-log-target"
MESH_CLIENT = "mesh-log-client"
MESH_SERVICE = "mesh-log-target"
MESH_CASE = "saf-k8s-1001-007-mesh-probe"
MESH_BODY_MARKER = "SYNTHETIC_ONLY_NO_REAL_DATA_1001_007_MESH_BODY"
ISTIO_VERSION = "1.32.0"
ISTIO_PILOT_IMAGE = (
    "docker.io/istio/pilot:1.32.0@sha256:"
    "5383df363d976589a51ab438831f82e9b5303dfc42128f2fb1f493b3f6acca78"
)
ISTIO_PROXY_IMAGE = (
    "docker.io/istio/proxyv2:1.32.0@sha256:"
    "b8d47c6d8d6e4b3fee7ae1e6f44339ec13091c24dc07f113a35efb0141a688d0"
)
ISTIO_RELEASE_SHA256 = {
    "Linux-x86_64": "b9cc0d427e2742b63ade28e15332a4b5da37ebf2d777a25ba22cc91bbfd51fbf",
    "Linux-arm64": "76f220746c75b6b0098d752da941ed91afc4e0cfd6722b853172d764fb6c2173",
    "Darwin-arm64": "1d9a82445c2395f85ce3a165dc90e182ad4e52214f85c18e93db274fd6d82fbb",
    "Darwin-x86_64": "803f30507ba687f88e10ea9b6736dfb77fcc3c66c1d3ce8dc71420bfcfe27d6c",
}
MESH_LOG_FORMAT = (
    "SAF1001|%REQ(:METHOD)%|%REQ(:PATH)%|%RESPONSE_CODE%|"
    "%BYTES_RECEIVED%|%BYTES_SENT%|%REQ(X-SAF-CASE)%"
)


def _install_mesh_access_log(lab, workdir):
    # Same pinned release, archive digests and image pins as published
    # SAF-K8S-0505-005; no unpinned mesh images or third-party workload.
    import hashlib
    import platform
    import tarfile

    system, machine = platform.system(), platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "x86_64" if machine in ("x86_64", "amd64") else None
    if arch is None:
        lab.block(f"Unsupported host architecture for Istio release archive: {machine}")
    expected = ISTIO_RELEASE_SHA256.get(f"{system}-{arch}")
    if not expected:
        lab.block(f"No verified Istio {ISTIO_VERSION} release digest for host {system}-{arch}")
    release_os = "osx" if system == "Darwin" else system.lower()
    release_arch = "amd64" if arch == "x86_64" else arch
    filename = f"istio-{ISTIO_VERSION}-{release_os}-{release_arch}.tar.gz"
    archive = workdir / filename
    lab.command("curl", "--fail", "--location", "--retry", "3", "--output", str(archive),
                f"https://github.com/istio/istio/releases/download/{ISTIO_VERSION}/{filename}", timeout=240)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        lab.block("Istio release archive SHA-256 mismatch")
    member_name = f"istio-{ISTIO_VERSION}/bin/istioctl"
    with tarfile.open(archive, "r:gz") as bundle:
        member = bundle.getmember(member_name)
        if not member.isfile():
            lab.block(f"Istio release archive has no regular file at {member_name}")
        source = bundle.extractfile(member)
        if source is None:
            lab.block(f"Cannot read Istio release member {member_name}")
        installer = workdir / member_name
        installer.parent.mkdir(parents=True, exist_ok=True)
        installer.write_bytes(source.read())
        installer.chmod(0o755)
    settings = workdir / "istio-1001-007.json"
    settings.write_text(json.dumps({
        "apiVersion": "install.istio.io/v1alpha1", "kind": "IstioOperator",
        "spec": {
            "profile": "minimal",
            "values": {"pilot": {"image": ISTIO_PILOT_IMAGE}},
            "meshConfig": {"accessLogFile": "/dev/stdout", "accessLogFormat": MESH_LOG_FORMAT},
        },
    }), encoding="utf-8")
    lab.command(str(installer), "install", "--kubeconfig", str(lab.kubeconfig),
                "--context", f"kind-{lab.cluster}", "-f", str(settings), "-y", timeout=280)
    lab.kubectl("-n", "istio-system", "rollout", "status", "deployment/istiod",
                "--timeout=90s", timeout=100)
    deployment = json.loads(lab.kubectl("-n", "istio-system", "get", "deployment/istiod", "-o", "json").stdout)
    images = [c["image"] for c in deployment["spec"]["template"]["spec"]["containers"]]
    lab.check("positive", "Istio 1.32.0 control plane matches the published pinned fixture",
              ISTIO_PILOT_IMAGE in images,
              {"istio_version": ISTIO_VERSION, "pilot_image_matches_pin": ISTIO_PILOT_IMAGE in images})


def _mesh_pod(lab, name, command):
    pod = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "labels": {"app": name},
                     "annotations": {"sidecar.istio.io/proxyImage": ISTIO_PROXY_IMAGE}},
        "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "containers": [{"name": "workload", "image": WORKLOAD_IMAGE,
                             "command": command,
                             "securityContext": {"allowPrivilegeEscalation": False,
                                                  "runAsNonRoot": True, "runAsUser": 10001,
                                                  "seccompProfile": {"type": "RuntimeDefault"},
                                                  "capabilities": {"drop": ["ALL"]}},
                             "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}]}],
            "volumes": [{"name": "fixture", "configMap": {"name": "mesh-access-fixture"}}],
        },
    }
    lab.kubectl("-n", MESH_NAMESPACE, "create", "-f", "-", payload=json.dumps(pod))
    lab.kubectl("-n", MESH_NAMESPACE, "wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=95s", timeout=105)
    state = json.loads(lab.kubectl("-n", MESH_NAMESPACE, "get", "pod", name, "-o", "json").stdout)
    containers = [*state["spec"]["containers"], *(
        c for c in state["spec"].get("initContainers", []) if c.get("restartPolicy") == "Always")]
    proxies = [c["image"] for c in containers if c["name"] == "istio-proxy"]
    lab.check("positive", f"{MESH_NAMESPACE}/{name} has the pinned Istio sidecar",
              proxies == [ISTIO_PROXY_IMAGE], {"proxy_image_matches_pin": proxies == [ISTIO_PROXY_IMAGE]})


def _run_mesh_access_log(lab):
    # The companion namespace is isolated from the original finite Pods.
    lab.kubectl("create", "namespace", MESH_NAMESPACE)
    lab.kubectl("label", "namespace", MESH_NAMESPACE, "istio-injection=enabled")
    work = lab.kubeconfig.parent
    _install_mesh_access_log(lab, work)
    server_source = '''from http.server import BaseHTTPRequestHandler, HTTPServer\nMARKER = "SYNTHETIC_ONLY_NO_REAL_DATA_1001_007_MESH_BODY"\nclass H(BaseHTTPRequestHandler):\n def do_POST(self):\n  n=int(self.headers.get("Content-Length", "0")); body=self.rfile.read(n)\n  ok=(self.path=="/submit" and body==MARKER.encode() and self.headers.get("X-SAF-Case")=="saf-k8s-1001-007-mesh-probe")\n  self.send_response(204 if ok else 400); self.end_headers()\n def log_message(self, *args): pass\nHTTPServer(("0.0.0.0",8080),H).serve_forever()\n'''
    client_source = '''import http.client\nc=http.client.HTTPConnection("mesh-log-target",8080,timeout=8)\nc.request("POST","/submit",b"SYNTHETIC_ONLY_NO_REAL_DATA_1001_007_MESH_BODY",{"X-SAF-Case":"saf-k8s-1001-007-mesh-probe"})\nr=c.getresponse(); print(r.status); r.read(); c.close()\n'''
    # Use a case-local ConfigMap payload; fixture code is synthetic and contains no secret.
    fixture = {"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"mesh-access-fixture","namespace":MESH_NAMESPACE},
               "data":{"mesh_server.py":server_source,"mesh_client.py":client_source}}
    lab.kubectl("-n", MESH_NAMESPACE, "create", "-f", "-", payload=json.dumps(fixture))
    server_command = ["python", "-B", "/fixture/mesh_server.py"]
    _mesh_pod(lab, MESH_SERVER, server_command)
    service = {"apiVersion":"v1","kind":"Service","metadata":{"name":MESH_SERVICE,"namespace":MESH_NAMESPACE},
               "spec":{"selector":{"app":MESH_SERVER},"ports":[{"name":"http","port":8080,"targetPort":8080}]}}
    lab.kubectl("-n", MESH_NAMESPACE, "create", "-f", "-", payload=json.dumps(service))
    _mesh_pod(lab, MESH_CLIENT, ["python", "-c", "import time; time.sleep(600)"])
    result = lab.kubectl("-n", MESH_NAMESPACE, "exec", MESH_CLIENT, "-c", "workload", "--",
                         "python", "-B", "/fixture/mesh_client.py", timeout=15)
    lab.check("positive", "One fixed local synthetic HTTP exchange reaches the owned mesh service",
              result.stdout.strip() == "204", {"http_status_204": result.stdout.strip() == "204"})

    # Read effective config and actual destination proxy output, but only retain minimized booleans.
    mesh_config = json.loads(lab.kubectl("-n", "istio-system", "get", "configmap", "istio", "-o", "json").stdout)
    mesh_text = mesh_config.get("data", {}).get("mesh", "")
    no_body_directive = not any(term in MESH_LOG_FORMAT.lower() for term in
                                ("request_body", "response_body", "%req_body%", "%resp_body%"))
    config_match = "accessLogFile: /dev/stdout" in mesh_text and MESH_LOG_FORMAT in mesh_text
    lab.check("positive", "Effective mesh config uses the pinned metadata-only access log format",
              config_match and no_body_directive,
              {"effective_file_stdout": "accessLogFile: /dev/stdout" in mesh_text,
               "format_matches_fixture": MESH_LOG_FORMAT in mesh_text,
               "configured_body_directives_absent": no_body_directive})

    deadline = time.monotonic() + 15
    selected = []
    while time.monotonic() < deadline:
        message = subprocess.run(
            ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
             "-n", MESH_NAMESPACE, "logs", MESH_SERVER, "-c", "istio-proxy"],
            env=lab.env, capture_output=True, text=True, timeout=10,
        )
        if message.returncode != 0:
            lab.block("Could not read the owned mesh sidecar log")
        rows = message.stdout.splitlines()
        selected = [row for row in rows if row.startswith("SAF1001|") and MESH_CASE in row]
        if selected:
            break
        time.sleep(0.3)
    fields = selected[0].split("|") if len(selected) == 1 else []
    expected = (len(fields) == 7 and fields[0] == "SAF1001" and fields[1] == "POST"
                and fields[2] == "/submit" and fields[3] == "204"
                and fields[4].isdigit() and int(fields[4]) == len(MESH_BODY_MARKER.encode())
                and fields[5] == "0" and fields[6] == MESH_CASE)
    body_absent = bool(selected) and all(MESH_BODY_MARKER not in row for row in selected)
    lab.check("positive", "Actual destination Envoy access log emits one correlated metadata record without the body",
              expected and body_absent,
              {"matching_log_records": len(selected), "method_path_status_match": expected,
               "byte_count_fields_numeric": len(fields) == 7 and fields[4].isdigit() and fields[5].isdigit(),
               "case_header_matches": len(fields) == 7 and fields[6] == MESH_CASE,
               "synthetic_body_marker_absent": body_absent})


# Preserve the published three observations; add four mesh-specific observations.
def run(lab):
    _run_local_telemetry(lab)
    _run_mesh_access_log(lab)
