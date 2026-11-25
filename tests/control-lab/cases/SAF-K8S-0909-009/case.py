"""Native Qdrant JWT collection authorization fixture for SAF-K8S."""
from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
import secrets
import time
from tempfile import TemporaryDirectory
from pathlib import Path

HERE = Path(__file__).resolve().parent
NS = "saf-test"
QDRANT = "fixture-qdrant"
PVC = "fixture-qdrant-data"
BASELINE = "fixture-qdrant-baseline"
CLIENT_A = "fixture-qdrant-alpha"
CLIENT_B = "fixture-qdrant-beta"
CLIENT_A_READER = "fixture-qdrant-alpha-reader"
EXPIRED_READER = "fixture-qdrant-expired-reader"
ADMIN_CLIENT = "fixture-qdrant-approved-admin"
TLS = "fixture-qdrant-tls"
CREDS = "fixture-qdrant-credentials"
CODE = "fixture-qdrant-code"
ALPHA = "fixture-alpha"
BETA = "fixture-beta"
QDRANT_IMAGE = "ghcr.io/qdrant/qdrant/qdrant:v1.20.2-unprivileged@sha256:ebddd1eb689137d3433e845f3e08bae25bcb2e1fda823ff12544bfd45910a5ab"
SCOPE = (
    "A pinned local Qdrant open-source engine enforces its native JWT RBAC on two synthetic "
    "collections over TLS. A coarse read token reaches both owned collections. "
    "Two separate scoped tokens read and write their assigned collections. "
    "Missing credentials and opposite-collection reads and writes are denied. "
    "A scoped read token and scoped read/write token are denied a harmless collection-create "
    "management action without changing state; an explicit global manage JWT can create, inspect, "
    "and remove only that owned synthetic metadata object. The native endpoint compares an expired "
    "and a current signed credential with the same collection read grant."
)


def load_runtime(lab):
    source = HERE.parent / "SAF-K8S-0908-001" / "case.py"
    if not source.is_file():
        root = next((path for path in HERE.parents if (path / "saf-k8s-publish").is_dir()), None)
        if root is not None:
            source = root / "saf-k8s-publish/tests/control-lab/cases/SAF-K8S-0908-001/case.py"
    if not source.is_file():
        lab.block("The adjacent pinned runtime helper is unavailable")
    spec = importlib.util.spec_from_file_location("saf_k8s_0908_001_runtime", source)
    if spec is None or spec.loader is None:
        lab.block("Could not load the actual adjacent SAF-K8S-0908-001 runtime helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_runtime(lab)


def load_engine(lab):
    reference = "saf-k8s-fixture/qdrant:1.20.2-ebddd1eb6891"
    inspect = ("docker", "image", "inspect", "--format", "{{.Id}}")
    expected = lab.command(*inspect, QDRANT_IMAGE, allow_failure=True)
    if expected.returncode:
        lab.command("docker", "image", "pull", QDRANT_IMAGE, timeout=240)
        expected = lab.command(*inspect, QDRANT_IMAGE)
    cached = lab.command(*inspect, reference, allow_failure=True)
    if cached.returncode:
        lab.command("docker", "image", "tag", QDRANT_IMAGE, reference)
        cached = lab.command(*inspect, reference)
    if not expected.stdout.strip() or expected.stdout.strip() != cached.stdout.strip():
        lab.block("The cached Qdrant reference does not match the pinned fixture")
    platform = lab.command("docker", "image", "inspect", "--format",
                           "{{.Os}}/{{.Architecture}}", reference).stdout.strip()
    with TemporaryDirectory(dir=lab.kubeconfig.parent) as temp:
        archive = str(Path(temp) / "qdrant.tar")
        lab.command("docker", "image", "save", "--platform", platform, "--output",
                    archive, reference, timeout=120)
        lab.command("kind", "load", "image-archive", archive, "--name", lab.cluster, timeout=120)
    return reference


def create(lab, kind, name, **fields):
    return lab.create({"apiVersion": "v1", "kind": kind,
                       "metadata": {"name": name, "namespace": NS}, **fields})


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwt(key, grants, *, lifetime=1800):
    now = int(time.time())
    header = b64url(b'{"alg":"HS256","typ":"JWT"}')
    payload = b64url(json.dumps({"exp": now + lifetime, "access": grants},
                                sort_keys=True, separators=(",", ":")).encode())
    signing = (header + "." + payload).encode()
    sig = hmac.new(key.encode(), signing, hashlib.sha256).digest()
    return (signing.decode() + "." + b64url(sig)).encode()


def setup(lab, image, engine):
    key_path = lab.kubeconfig.parent / "qdrant-admin-key"
    alpha_path = lab.kubeconfig.parent / "qdrant-alpha-token"
    alpha_reader_path = lab.kubeconfig.parent / "qdrant-alpha-reader-token"
    expired_reader_path = lab.kubeconfig.parent / "qdrant-expired-reader-token"
    beta_path = lab.kubeconfig.parent / "qdrant-beta-token"
    baseline_path = lab.kubeconfig.parent / "qdrant-baseline-token"
    admin_token_path = lab.kubeconfig.parent / "qdrant-approved-admin-token"
    # Secrets are generated into private files; kubectl receives only file paths.
    admin_key = secrets.token_urlsafe(32)
    key_path.write_text(admin_key)
    key_path.chmod(0o600)
    alpha_path.write_bytes(jwt(admin_key, [
        {"collection": ALPHA, "access": "rw"}]))
    alpha_read_grant = [{"collection": ALPHA, "access": "r"}]
    alpha_reader_path.write_bytes(jwt(admin_key, alpha_read_grant))
    expired_reader_path.write_bytes(jwt(admin_key, alpha_read_grant, lifetime=-1800))
    beta_path.write_bytes(jwt(admin_key, [
        {"collection": BETA, "access": "rw"}]))
    admin_token_path.write_bytes(jwt(admin_key, "m"))
    alpha_path.chmod(0o600)
    alpha_reader_path.chmod(0o600)
    expired_reader_path.chmod(0o600)
    beta_path.chmod(0o600)
    baseline_path.write_bytes(jwt(admin_key, [
        {"collection": name, "access": "r"} for name in (ALPHA, BETA)]))
    baseline_path.chmod(0o600)
    admin_token_path.chmod(0o600)

    cert = lab.kubeconfig.parent / "qdrant.crt"
    cert_key = lab.kubeconfig.parent / "qdrant.key"
    lab.command("openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
                "-subj", f"/CN={QDRANT}.{NS}.svc", "-addext",
                f"subjectAltName=DNS:{QDRANT}.{NS}.svc", "-addext",
                "basicConstraints=critical,CA:TRUE", "-addext",
                "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
                "-keyout", str(cert_key), "-out", str(cert))
    lab.kubectl("create", "secret", "tls", TLS, "--key=" + str(cert_key),
                "--cert=" + str(cert), "-o", "name")
    lab.kubectl("create", "secret", "generic", CREDS,
                "--from-file=admin-key=" + str(key_path),
                "--from-file=alpha-token=" + str(alpha_path),
                "--from-file=alpha-reader-token=" + str(alpha_reader_path),
                "--from-file=expired-reader-token=" + str(expired_reader_path),
                "--from-file=beta-token=" + str(beta_path),
                "--from-file=baseline-token=" + str(baseline_path),
                "--from-file=admin-token=" + str(admin_token_path), "-o", "name")
    create(lab, "ConfigMap", "fixture-qdrant-config", immutable=True, data={"config.yaml": (
        "telemetry_disabled: true\nservice:\n  host: 0.0.0.0\n  http_port: 6333\n  grpc_port: null\n"
        "  enable_tls: true\n  jwt_rbac: true\n"
        "  enable_cors: false\n"
        "tls:\n  cert: /tls/tls.crt\n  key: /tls/tls.key\n"
        "storage:\n  storage_path: /qdrant/storage\n  snapshots_path: /qdrant/storage/snapshots\n"
    )})
    create(lab, "ConfigMap", CODE, immutable=True,
           data={"qdrant_fixture.py": (HERE / "qdrant_fixture.py").read_text()})
    # PVC is created before the pod, but binding is awaited only after the pod has
    # been scheduled, supporting WaitForFirstConsumer storage classes.
    create(lab, "PersistentVolumeClaim", PVC, spec={
        "accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}
    })
    create(lab, "Pod", QDRANT, spec={
        "restartPolicy": "Always", "automountServiceAccountToken": False, "securityContext": {"runAsNonRoot": True,
        "runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000,
        "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "qdrant", "image": engine,
            "imagePullPolicy": "Never",
            "command": ["/bin/sh", "-ec", "export QDRANT__SERVICE__API_KEY=\"$(cat /run/credentials/admin-key)\"; exec /qdrant/qdrant --config-path /etc/qdrant/config.yaml"],
            "ports": [{"name": "https", "containerPort": 6333}],
            "volumeMounts": [
                {"name": "config", "mountPath": "/etc/qdrant", "readOnly": True},
                {"name": "tls", "mountPath": "/tls", "readOnly": True},
                {"name": "credentials", "mountPath": "/run/credentials", "readOnly": True},
                {"name": "data", "mountPath": "/qdrant/storage"}],
            "readinessProbe": {"tcpSocket": {"port": 6333}, "periodSeconds": 2,
                               "failureThreshold": 60},
            "securityContext": {"allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "100m", "memory": "128Mi"},
                          "limits": {"cpu": "1", "memory": "512Mi"}}}],
        "volumes": [
            {"name": "config", "configMap": {"name": "fixture-qdrant-config"}},
            {"name": "tls", "secret": {"secretName": TLS, "defaultMode": 0o440}},
            {"name": "credentials", "secret": {"secretName": CREDS, "items": [
                {"key": "admin-key", "path": "admin-key"}], "defaultMode": 0o440}},
            {"name": "data", "persistentVolumeClaim": {"claimName": PVC}}]})
    # Add the selector label required by the ClusterIP service.
    lab.kubectl("-n", NS, "label", "pod/" + QDRANT, "app=" + QDRANT)
    create(lab, "Service", QDRANT, spec={"selector": {"app": QDRANT},
        "ports": [{"name": "https", "port": 6333, "targetPort": 6333}]})
    # Pod scheduling precedes PVC binding wait for delayed binding provisioners.
    lab.kubectl("-n", NS, "wait", "--for=jsonpath={.status.phase}=Bound", "pvc/" + PVC,
                "--timeout=180s", timeout=190)
    lab.kubectl("-n", NS, "wait", "--for=condition=Ready", "pod/" + QDRANT,
                "--timeout=150s", timeout=160)

    for name, token_key in (("fixture-qdrant-bootstrap", "admin-key"),
                            (CLIENT_A, "alpha-token"),
                            (CLIENT_A_READER, "alpha-reader-token"),
                            (EXPIRED_READER, "expired-reader-token"),
                            (CLIENT_B, "beta-token"), (BASELINE, "baseline-token"),
                            (ADMIN_CLIENT, "admin-token")):
        create(lab, "Pod", name, spec={
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534,
                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "client", "image": image, "imagePullPolicy": "Never",
                "command": ["sleep", "3600"], "volumeMounts": [
                    {"name": "code", "mountPath": "/fixture", "readOnly": True},
                    {"name": "credential", "mountPath": "/identity", "readOnly": True},
                    {"name": "trust", "mountPath": "/trust", "readOnly": True}],
                "securityContext": {"allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                              "limits": {"cpu": "200m", "memory": "128Mi"}}}],
            "volumes": [{"name": "code", "configMap": {"name": CODE}},
                {"name": "credential", "secret": {"secretName": CREDS, "items": [
                    {"key": token_key, "path": "token"}], "defaultMode": 0o440}},
                {"name": "trust", "configMap": {"name": "fixture-qdrant-trust"}}]})
    # Put the TLS trust certificate in a separate public config map.
    create(lab, "ConfigMap", "fixture-qdrant-trust", immutable=True,
           data={"ca.crt": cert.read_text()})
    for name in ("fixture-qdrant-bootstrap", CLIENT_A, CLIENT_A_READER,
                 CLIENT_B, BASELINE, ADMIN_CLIENT, EXPIRED_READER):
        lab.kubectl("-n", NS, "wait", "--for=condition=Ready", "pod/" + name,
                    "--timeout=120s", timeout=130)


def call(lab, pod, operation, principal=None):
    args = ["-n", NS, "exec", "pod/" + pod, "--", "python",
            "/fixture/qdrant_fixture.py", operation, f"https://{QDRANT}.{NS}.svc:6333"]
    if principal:
        args.append(principal)
    result = lab.kubectl(*args, timeout=35)
    return json.loads(result.stdout)


def run(lab):
    image = load_runtime(lab)
    setup(lab, image, load_engine(lab))
    init = call(lab, "fixture-qdrant-bootstrap", "initialize")
    lab.kubectl("-n", NS, "delete", "pod/fixture-qdrant-bootstrap", "--wait=true")
    broad = call(lab, BASELINE, "baseline")
    baseline_ok = (init.get("collections_ready") and broad.get("markers") ==
                   ["synthetic-alpha", "synthetic-beta"])
    lab.check("red", "The coarse read grant allows access to both fixture collections", baseline_ok, broad)

    alpha = call(lab, CLIENT_A, "governed", ALPHA)
    beta = call(lab, CLIENT_B, "governed", BETA)
    anonymous = call(lab, CLIENT_A, "anonymous")
    green_ok = (anonymous.get("status") in (401, 403) and alpha.get("own_read") and alpha.get("own_write") and alpha.get("own_count") == 2
                and alpha.get("opposite_read_status") in (401, 403)
                and alpha.get("opposite_write_status") in (401, 403)
                and beta.get("own_read") and beta.get("own_write") and beta.get("own_count") == 2
                and beta.get("opposite_read_status") in (401, 403)
                and beta.get("opposite_write_status") in (401, 403))
    lab.check("green", "Native JWT RBAC allows own-collection read/write and denies the opposite collection",
              bool(green_ok), {"alpha": alpha, "beta": beta, "no_credential": anonymous})

    ending_alpha = call(lab, CLIENT_A, "count", ALPHA)
    ending_beta = call(lab, CLIENT_B, "count", BETA)
    unchanged = ending_alpha == ending_beta == {"status": 200, "count": 2}
    positive_ok = (unchanged and alpha.get("own_marker") == "synthetic-alpha" and beta.get("own_marker") == "synthetic-beta"
                   and alpha.get("opposite_read_denied") and beta.get("opposite_read_denied"))
    lab.check("positive", "Each authorized principal receives its own synthetic result and cannot read the other collection",
              bool(positive_ok), {"alpha_own_result": alpha.get("own_marker") == "synthetic-alpha",
                                  "beta_own_result": beta.get("own_marker") == "synthetic-beta",
                                  "denied_writes_left_exact_collection_counts": unchanged})

    # Verify the distinct global-manage boundary using one fixed synthetic
    # metadata object. Never attempt to create, overwrite, or remove a preexisting object.
    admin_before = call(lab, ADMIN_CLIENT, "admin-probe-exists")
    precondition = admin_before.get("status") == 200 and admin_before.get("exists") is False
    admin_result = {
        "fresh_owned_name_absent_before_probe": precondition,
        "scoped_reader_denied_without_state_change": False,
        "scoped_writer_denied_without_state_change": False,
        "approved_admin_created_and_inspected": False,
        "approved_admin_removed_owned_object": False,
    }
    writer_denied = reader_denied = None
    created_by_fixture = False
    try:
        if precondition:
            reader_denied = call(lab, CLIENT_A_READER, "admin-probe-create")
            after_reader = call(lab, ADMIN_CLIENT, "admin-probe-exists")
            admin_result["scoped_reader_denied_without_state_change"] = (
                reader_denied.get("status") == 403
                and after_reader.get("status") == 200
                and after_reader.get("exists") is False)

            writer_denied = call(lab, CLIENT_A, "admin-probe-create")
            after_writer = call(lab, ADMIN_CLIENT, "admin-probe-exists")
            admin_result["scoped_writer_denied_without_state_change"] = (
                writer_denied.get("status") == 403
                and after_writer.get("status") == 200
                and after_writer.get("exists") is False)

            created = call(lab, ADMIN_CLIENT, "admin-probe-create")
            after_create = call(lab, ADMIN_CLIENT, "admin-probe-exists")
            created_by_fixture = (after_create.get("status") == 200
                                  and after_create.get("exists") is True)
            inspected = (call(lab, ADMIN_CLIENT, "admin-probe-inspect")
                         if created_by_fixture else {"metadata_read": False})
            admin_result["approved_admin_created_and_inspected"] = (
                created.get("status") in (200, 201)
                and created_by_fixture
                and inspected.get("metadata_read") is True)

            if created_by_fixture:
                deleted = call(lab, ADMIN_CLIENT, "admin-probe-delete")
                after_delete = call(lab, ADMIN_CLIENT, "admin-probe-exists")
                admin_result["approved_admin_removed_owned_object"] = (
                    deleted.get("status") == 200
                    and after_delete.get("status") == 200
                    and after_delete.get("exists") is False)
                if after_delete.get("exists") is False:
                    created_by_fixture = False
    finally:
        # Cleanup is restricted to the exact name after this run proved it
        # absent and then observed the approved create path make it present.
        if precondition and created_by_fixture:
            call(lab, ADMIN_CLIENT, "admin-probe-delete")

    admin_boundary_ok = all(admin_result.values())
    admin_observations = {
        **admin_result,
        "scoped_reader_create_status": None if reader_denied is None else reader_denied.get("status"),
        "scoped_writer_create_status": None if writer_denied is None else writer_denied.get("status"),
    }
    lab.check("green", "Scoped read and read/write credentials cannot create a collection; the approved manage token can create, inspect, and remove the isolated metadata object",
              bool(admin_boundary_ok), admin_observations)

    expired = call(lab, EXPIRED_READER, "count", ALPHA)
    current = call(lab, CLIENT_A_READER, "count", ALPHA)
    lifetime_result = {
        "expired_status": expired.get("status"),
        "expired_data_absent": expired.get("count") is None,
        "current_same_grant_status": current.get("status"),
        "current_same_grant_exact_count": current.get("count") == 2,
    }
    lab.check("green", "The native Qdrant endpoint rejects an expired signed reader and accepts the current equivalent grant",
              expired.get("status") in (401, 403) and lifetime_result["expired_data_absent"]
              and current == {"status": 200, "count": 2}, lifetime_result)

    evidence = {"engine": "Qdrant", "image": QDRANT_IMAGE, "baseline": {
        "coarse_grant_reads_both_collections": bool(baseline_ok),
        "native_markers": broad.get("markers")},
        "governed": {"no_credential_status": anonymous.get("status"),
            "alpha_own_read_write": bool(alpha.get("own_read") and alpha.get("own_write")),
            "beta_own_read_write": bool(beta.get("own_read") and beta.get("own_write")),
            "alpha_opposite_read_status": alpha.get("opposite_read_status"),
            "alpha_opposite_write_status": alpha.get("opposite_write_status"),
            "beta_opposite_read_status": beta.get("opposite_read_status"),
            "beta_opposite_write_status": beta.get("opposite_write_status")},
        "positive": {"alpha_own_marker": alpha.get("own_marker"),
            "beta_own_marker": beta.get("own_marker"), "denied_writes_left_counts_unchanged": unchanged}}
    evidence["admin_boundary"] = admin_observations
    evidence["credential_expiration"] = lifetime_result
    (lab.evidence / "qdrant-native-authz-observations.json").write_text(
        json.dumps(evidence, sort_keys=True, indent=2) + "\n")
