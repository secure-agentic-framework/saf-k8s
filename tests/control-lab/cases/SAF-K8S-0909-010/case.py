"""Pinned Qdrant transport and persistence fixture for SAF-K8S."""
from __future__ import annotations

import importlib.util
import json
import secrets
from pathlib import Path

HERE = Path(__file__).resolve().parent
NS = "saf-test"  # owned by the harness
QDRANT = "fixture-qdrant-tls"
PVC = "fixture-qdrant-tls-data"
BASELINE = "fixture-qdrant-plain"
BACKUP = "fixture-qdrant-encrypted-backup"
TOOLS = "saf-lab-disk-encryption-fixture:alpine3.22"
SERVICE = QDRANT
TLS = "fixture-qdrant-tls-cert"
KEY = "fixture-qdrant-api-key"
CODE = "fixture-qdrant-transport-code"
CLIENT = "fixture-qdrant-transport-client"
COLLECTION = "fixture-transport-synthetic"
QDRANT_IMAGE = (
    "ghcr.io/qdrant/qdrant/qdrant:v1.20.2-unprivileged@sha256:"
    "ebddd1eb689137d3433e845f3e08bae25bcb2e1fda823ff12544bfd45910a5ab"
)
SCOPE = (
    "A pinned local Qdrant serves the unencrypted comparator and an independently verified TLS "
    "endpoint. A retrieved point survives recreation of the governed Pod. A native approved "
    "collection snapshot is exported to memory, encrypted into LUKS on a distinct persistent "
    "claim, recovered with the separate key, and restored into a distinct Qdrant collection. "
    "The active Qdrant data volume encryption is outside this fixture."
)


def dependency(suffix):
    source = HERE.parent / ("SAF-K8S-"+suffix) / "case.py"
    spec = importlib.util.spec_from_file_location("saf_transport_runtime_"+suffix, source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def disk_image(lab):
    source = HERE.parent / "SAF-K8S-0102-001" / "Dockerfile"
    cached = lab.command("docker", "image", "inspect", "--format", "{{.Id}}", TOOLS, allow_failure=True)
    if cached.returncode:
        lab.command("docker", "build", "-q", "-t", TOOLS, "-f", str(source), str(source.parent), timeout=200)
    lab.command("kind", "load", "docker-image", TOOLS, "--name", lab.cluster, timeout=120)


def create(lab, kind, name, api="v1", **fields):
    return lab.create({"apiVersion": api, "kind": kind,
                       "metadata": {"name": name, "namespace": NS}, **fields})


def credentials(lab):
    cert = lab.kubeconfig.parent / "qdrant-transport.crt"
    private_key = lab.kubeconfig.parent / "qdrant-transport.key"
    api_key = lab.kubeconfig.parent / "qdrant-transport-api-key"
    lab.command("openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
                "-subj", f"/CN={SERVICE}.{NS}.svc", "-addext",
                f"subjectAltName=DNS:{SERVICE}.{NS}.svc", "-addext",
                "basicConstraints=critical,CA:TRUE", "-addext",
                "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
                "-keyout", str(private_key), "-out", str(cert))
    value = secrets.token_urlsafe(32)
    api_key.write_text(value + "\n")
    api_key.chmod(0o600)
    lab.kubectl("create", "secret", "tls", TLS, "--key=" + str(private_key),
                "--cert=" + str(cert), "-n", NS, "-o", "name")
    lab.kubectl("create", "secret", "generic", KEY, "--from-file=api-key=" + str(api_key),
                "-n", NS, "-o", "name")
    create(lab, "ConfigMap", "fixture-qdrant-transport-trust", immutable=True,
           data={"ca.crt": cert.read_text(encoding="utf-8")})


def qdrant_pod(lab, engine):
    create(lab, "Pod", QDRANT, spec={
        "restartPolicy": "Always",
        "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000,
                            "fsGroup": 1000,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{
            "name": "qdrant", "image": engine, "imagePullPolicy": "Never",
            "command": ["/bin/sh", "-ec",
                        "export QDRANT__SERVICE__API_KEY=\"$(cat /run/key/api-key)\"; "
                        "exec /qdrant/qdrant --config-path /etc/qdrant/config.yaml"],
            "ports": [{"name": "https", "containerPort": 6333}],
            "volumeMounts": [
                {"name": "config", "mountPath": "/etc/qdrant", "readOnly": True},
                {"name": "tls", "mountPath": "/tls", "readOnly": True},
                {"name": "key", "mountPath": "/run/key", "readOnly": True},
                {"name": "data", "mountPath": "/qdrant/storage"},
                {"name": "snapshots", "mountPath": "/qdrant/snapshots"}],
            "readinessProbe": {"tcpSocket": {"port": 6333}, "periodSeconds": 2,
                               "failureThreshold": 60},
            "securityContext": {"allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "100m", "memory": "128Mi"},
                          "limits": {"cpu": "1", "memory": "512Mi"}},
        }],
        "volumes": [
            {"name": "config", "configMap": {"name": "fixture-qdrant-transport-config"}},
            {"name": "tls", "secret": {"secretName": TLS, "defaultMode": 288}},
            {"name": "key", "secret": {"secretName": KEY, "defaultMode": 288}},
            {"name": "data", "persistentVolumeClaim": {"claimName": PVC}},
            {"name": "snapshots", "emptyDir": {"medium": "Memory"}}],
    })
    lab.kubectl("-n", NS, "label", "pod/" + QDRANT, "app=" + QDRANT, "--overwrite")


def baseline_pod(lab, engine):
    create(lab, "ConfigMap", BASELINE, immutable=True, data={"config.yaml": (
        "telemetry_disabled: true\nservice:\n  host: 0.0.0.0\n  http_port: 6333\n  grpc_port: null\n"
        "  enable_tls: false\nstorage:\n  storage_path: /qdrant/storage\n  snapshots_path: /qdrant/storage/snapshots\n")})
    create(lab, "Pod", BASELINE, spec={
        "restartPolicy":"Never", "automountServiceAccountToken":False,
        "securityContext":{"runAsNonRoot":True,"runAsUser":1000,"fsGroup":1000,
                           "seccompProfile":{"type":"RuntimeDefault"}},
        "containers":[{"name":"qdrant","image":engine,"imagePullPolicy":"Never",
                       "command":["/qdrant/qdrant","--config-path","/baseline/config.yaml"],
                       "readinessProbe":{"tcpSocket":{"port":6333},"periodSeconds":1},
                       "volumeMounts":[{"name":"config","mountPath":"/baseline","readOnly":True},
                                       {"name":"data","mountPath":"/qdrant/storage"}],
                       "securityContext":{"allowPrivilegeEscalation":False,"readOnlyRootFilesystem":True,
                                          "capabilities":{"drop":["ALL"]}}}],
        "volumes":[{"name":"config","configMap":{"name":BASELINE}},{"name":"data","emptyDir":{}}]})
    lab.kubectl("label","pod/"+BASELINE,"app="+BASELINE)
    create(lab,"Service",BASELINE,spec={"selector":{"app":BASELINE},"ports":[{"port":6333}]})


def client_pod(lab, image):
    create(lab, "ConfigMap", CODE, immutable=True,
           data={"transport_fixture.py": (HERE / "transport_fixture.py").read_text(encoding="utf-8")})
    create(lab, "Pod", CLIENT, spec={
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "client", "image": image, "imagePullPolicy": "Never",
            "command": ["sleep", "3600"],
            "volumeMounts": [
                {"name": "code", "mountPath": "/fixture", "readOnly": True},
                {"name": "trust", "mountPath": "/trust", "readOnly": True},
                {"name": "key", "mountPath": "/identity", "readOnly": True},
                {"name":"work","mountPath":"/backup-work"}],
            "securityContext": {"allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                          "limits": {"cpu": "200m", "memory": "128Mi"}},
        },{
            "name":"disk","image":TOOLS,"imagePullPolicy":"Never","command":["sleep","3600"],
            "volumeMounts":[{"name":"work","mountPath":"/backup-work"},
                            {"name":"keys","mountPath":"/backup-keys"},
                            {"name":"vault","mountPath":"/backup-vault"}],
            "securityContext":{"allowPrivilegeEscalation":False,"readOnlyRootFilesystem":True,
                               "capabilities":{"drop":["ALL"]}},
            "resources":{"requests":{"cpu":"20m","memory":"32Mi"},"limits":{"cpu":"500m","memory":"256Mi"}}
        }],
        "volumes": [
            {"name": "code", "configMap": {"name": CODE}},
            {"name": "trust", "configMap": {"name": "fixture-qdrant-transport-trust"}},
            {"name": "key", "secret": {"secretName": KEY,
                     "items": [{"key": "api-key", "path": "api-key"}], "defaultMode": 288}},
            {"name":"work","emptyDir":{"medium":"Memory"}},
            {"name":"keys","emptyDir":{"medium":"Memory"}},
            {"name":"vault","persistentVolumeClaim":{"claimName":BACKUP}}],
    })


def observe(lab, operation):
    result = lab.kubectl("-n", NS, "exec", "pod/" + CLIENT, "-c", "client", "--", "python",
                         "/fixture/transport_fixture.py", operation,
                         f"{SERVICE}.{NS}.svc", COLLECTION, timeout=35)
    return json.loads(result.stdout)


def run(lab):
    image = dependency("0908-001").load_runtime(lab)
    engine = dependency("0909-009").load_engine(lab)
    disk_image(lab)
    credentials(lab)
    create(lab, "ConfigMap", "fixture-qdrant-transport-config", immutable=True,
           data={"config.yaml": (
               "telemetry_disabled: true\nservice:\n  host: 0.0.0.0\n  http_port: 6333\n"
               "  grpc_port: null\n  enable_tls: true\n"
               "  jwt_rbac: false\n  enable_cors: false\n"
               "tls:\n  cert: /tls/tls.crt\n  key: /tls/tls.key\n"
               "storage:\n  storage_path: /qdrant/storage\n  snapshots_path: /qdrant/snapshots\n")})
    create(lab, "PersistentVolumeClaim", PVC, spec={
        "accessModes": ["ReadWriteOnce"],
        "resources": {"requests": {"storage": "1Gi"}},
    })
    qdrant_pod(lab, engine)  # schedule a consumer before waiting for delayed binding
    create(lab, "Service", SERVICE, spec={"selector": {"app": QDRANT},
        "ports": [{"name": "https", "port": 6333, "targetPort": 6333}]})
    lab.kubectl("-n", NS, "wait", "--for=jsonpath={.status.phase}=Bound", "pvc/" + PVC,
                "--timeout=180s", timeout=190)
    lab.kubectl("-n", NS, "wait", "--for=condition=Ready", "pod/" + QDRANT,
                "--timeout=150s", timeout=160)
    baseline_pod(lab, engine)
    create(lab, "PersistentVolumeClaim", BACKUP, spec={
        "accessModes":["ReadWriteOnce"], "resources":{"requests":{"storage":"1Gi"}}})
    client_pod(lab, image)
    lab.kubectl("wait","--for=condition=Ready","pod/"+BASELINE,"--timeout=100s",timeout=110)
    lab.kubectl("-n", NS, "wait", "--for=condition=Ready", "pod/" + CLIENT,
                "--timeout=120s", timeout=130)

    transport = observe(lab, "transport")
    lab.check("red", "The baseline Qdrant listener answers the fixed request over plaintext HTTP",
              transport["baseline_accepts_plaintext"],
              {"baseline_accepts_plaintext": transport["baseline_accepts_plaintext"]})
    lab.check("green", "The governed Qdrant endpoint rejects plaintext and untrusted certificates",
              all(transport[name] for name in ("plaintext_http_rejected", "untrusted_certificate_rejected",
                                               "trusted_request_succeeded")), transport)
    storage = observe(lab, "initialize")
    lab.check("green", "Qdrant accepts only the CA-validated TLS client and persists the synthetic point",
              storage["tls_verified"] and storage["hostname_verified"]
              and storage["tls_version"] in ("TLSv1.2", "TLSv1.3")
              and storage["write_and_read_ok"], storage)

    lab.kubectl("-n", NS, "delete", "pod/" + QDRANT, "--wait=true")
    qdrant_pod(lab, engine)  # same PVC; schedule before checking its binding
    lab.kubectl("-n", NS, "wait", "--for=jsonpath={.status.phase}=Bound", "pvc/" + PVC,
                "--timeout=180s", timeout=190)
    lab.kubectl("-n", NS, "wait", "--for=condition=Ready", "pod/" + QDRANT,
                "--timeout=150s", timeout=160)
    recovered = observe(lab, "recover")
    lab.check("positive", "The owned synthetic point is readable after Qdrant Pod recreation",
              recovered["recovered"] and recovered["marker"] == "synthetic-cedar-v1", recovered)

    captured = observe(lab, "capture")
    media = lab.kubectl("exec","-i","pod/"+CLIENT,"-c","disk","--","sh","-s",
                        payload=(HERE/"backup-fixture.sh").read_text(),timeout=110)
    signals = set(media.stdout.splitlines())
    red = captured["native_snapshot_captured"] and "plaintext_marker_visible" in signals
    lab.check("red", "Unprotected export media exposes a known marker alongside the native snapshot",
              red, {"native_snapshot_captured": captured["native_snapshot_captured"],
                    "plaintext_marker_visible": "plaintext_marker_visible" in signals})
    green = {"luks_media_hides_marker": "luks_media_marker_hidden" in signals,
             "unrelated_key_denied": "unrelated_key_denied" in signals,
             "backup_contains_ciphertext_only": "persistent_vault_ciphertext_only" in signals}
    lab.check("green", "The persistent backup contains LUKS ciphertext and rejects an unrelated key",
              all(green.values()), green)
    restored = observe(lab, "restore")
    lab.check("positive", "The recovered bytes restore a separate native collection with the known point",
              "approved_key_roundtrip" in signals and all(restored.values()), restored)

    (lab.evidence/"qdrant-transport-observations.json").write_text(json.dumps(
        {"transport":transport, "persisted_live_point":recovered["recovered"],
         "backup_encryption":green, "authorized_restore":restored,
         "live_pvc_encryption":"unverified"}, sort_keys=True, indent=2)+"\n")
