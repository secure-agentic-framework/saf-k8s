"""Check independently retained Zot audit and HTTP events using Fluent Bit."""
from collections import Counter
import json
import hashlib
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
from contextlib import contextmanager

from lab import NODE_IMAGE

HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
CONFIG_OWNER = "system:serviceaccount:saf-test:registry-config-owner"
ZOT = "ghcr.io/project-zot/zot:v2.1.23@sha256:9d3de83ac2099e6f4843045b4c9b65b7e8baf40f92d28f54906dee9d4d390fd7"
PYTHON = "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
FLUENT_BIT = "cr.fluentbit.io/fluent/fluent-bit:5.1.2@sha256:d792375ca8e53be72fc25716c28f291f32c6fc6f4f31d12d0d14bc78cefe9226"
BUSYBOX = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
ACTOR = "fixture-publisher"
ADMIN_ACTOR = "fixture-registry-admin"
SINK_ACTOR = "fixture-forwarder"
REPO = "saf-test/audit-model"
AUDIT = "/events/audit.jsonl"
ACCESS = "/events/access.jsonl"
ADMIN_PATH = "/v2/_zot/ext/cosign"
RETRY_PATH = f"/v2/{REPO}/manifests/retry-503-v1"
SCOPE = (
    "One fresh Kind cluster runs two authenticated Zot v2.1.23 registries. The same "
    "inert OCI operations occur with forwarding off and on. Fluent Bit 5.1.2 ships "
    "native audit and HTTP access events to an independent HTTP receiver backed by a "
    "PVC. The receiver is replaced, retained events are compared, and a fresh event "
    "sequence is delivered. A separate exact inert registry access record receives "
    "one authenticated HTTP 503 before sink commit and is then accepted on retry. "
    "Covers model manifest publish, pull, retag and digest "
    "deletion plus one permitted admin-only Cosign public-key upload. Other permission and administrative event sources, loss recovery during "
    "long receiver outages, sender restart recovery, general deduplication, production access controls, "
    "SIEM delivery and retention are open. A final case-only "
    "Kubernetes configuration-owner update records a metadata-only API audit event for the named Zot config "
    "ConfigMap, forwards its exact event through a one-record projection to the protected sink, and compares "
    "one inert registry read before and after its access-policy revision. This is not a "
    "native Zot permission-change audit event or production GitOps identity proof."
)


def prepare_kind(lab, temporary):
    audit = temporary / "audit"
    audit.mkdir(mode=0o700)
    lab.audit_file = audit / "audit.log"
    content = (HERE / "kind.yaml.in").read_text()
    config = temporary / "kind.yaml"
    config.write_text(content.replace("@POLICY_PATH@", json.dumps(str(HERE / "audit-policy.yaml")))
                      .replace("@AUDIT_DIR@", json.dumps(str(audit))))
    return config


def _submit(lab, obj):
    lab.kubectl("create", "-f", "-", payload=json.dumps(obj))


def _configmap(lab, name, data):
    _submit(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                  "metadata": {"name": name}, "data": data})


def _volume(name, **reference):
    return {"name": name, **reference}


def _mount(name, path, *, read_only=False):
    return {"name": name, "mountPath": path, "readOnly": read_only}


def _container(name, image, mounts, *, command=None, args=None, ready_port=None):
    container = {
        "name": name, "image": image, "imagePullPolicy": "IfNotPresent", "volumeMounts": mounts,
        "resources": {"requests": {"cpu": "15m", "memory": "24Mi"},
                      "limits": {"cpu": "250m", "memory": "128Mi"}},
    }
    if command:
        container["command"] = command
    if args:
        container["args"] = args
    if ready_port:
        container["readinessProbe"] = {"tcpSocket": {"port": ready_port}, "periodSeconds": 1}
    return container


def _deployment(lab, name, containers, volumes, port=None):
    _submit(lab, {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name},
                  "spec": {"replicas": 1, "strategy": {"type": "Recreate"},
                           "selector": {"matchLabels": {"app": name}},
                           "template": {"metadata": {"labels": {"app": name}},
                                        "spec": {"automountServiceAccountToken": False,
                                                 "containers": containers, "volumes": volumes}}}})
    if port:
        _submit(lab, {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
                      "spec": {"selector": {"app": name},
                               "ports": [{"port": port, "targetPort": port}]}})


@contextmanager
def _temporary_forwarding_material():
    """Generate test-only CA, leaf and auth files without putting values in argv."""
    temporary = tempfile.TemporaryDirectory(prefix="saf-0905-040-forwarding-")
    root = Path(temporary.name)
    os.chmod(root, 0o700)
    ca_key, ca_csr, ca_cert = root / "ca.key", root / "ca.csr", root / "ca.pem"
    sink_key, sink_csr, sink_cert = root / "sink.key", root / "sink.csr", root / "sink.crt"
    ca_ext, sink_ext = root / "ca.ext", root / "sink.ext"
    username, password = root / "username", root / "password"
    wrong_password = root / "wrong-password"
    ca_ext.write_text("basicConstraints=critical,CA:TRUE,pathlen:0\n"
                      "keyUsage=critical,keyCertSign,cRLSign\n"
                      "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\n")
    sink_dns = "sink.saf-test.svc.cluster.local"
    sink_ext.write_text("basicConstraints=critical,CA:FALSE\n"
                        "keyUsage=critical,digitalSignature,keyEncipherment\n"
                        "extendedKeyUsage=serverAuth\n"
                        f"subjectAltName=DNS:{sink_dns}\n"
                        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
    username.touch(mode=0o600, exist_ok=False)
    username.write_text(SINK_ACTOR)
    password.touch(mode=0o600, exist_ok=False)
    valid_password = secrets.token_urlsafe(24)
    password.write_text(valid_password)
    wrong_password.touch(mode=0o600, exist_ok=False)
    invalid_password = secrets.token_urlsafe(24)
    while invalid_password == valid_password:
        invalid_password = secrets.token_urlsafe(24)
    wrong_password.write_text(invalid_password)
    commands = [
        ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key),
         "-out", str(ca_csr), "-subj", "/CN=SAF-K8S-0905-040 fixture CA"],
        ["openssl", "x509", "-req", "-in", str(ca_csr), "-signkey", str(ca_key), "-days", "2",
         "-extfile", str(ca_ext), "-out", str(ca_cert)],
        ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(sink_key),
         "-out", str(sink_csr), "-subj", f"/CN={sink_dns}"],
        ["openssl", "x509", "-req", "-in", str(sink_csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
         "-CAcreateserial", "-days", "2", "-extfile", str(sink_ext), "-out", str(sink_cert)],
    ]
    try:
        for command in commands:
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=20)
        for path in (ca_key, sink_key, username, password, wrong_password):
            os.chmod(path, 0o600)
        template = (Path(__file__).resolve().parent / "fluent-bit.yaml").read_text()
        rendered = template.replace("__SINK_USER__", json.dumps(SINK_ACTOR))
        rendered = rendered.replace("__SINK_PASSWORD__", json.dumps(valid_password))
        forwarding_config = root / "fluent-bit.yaml"
        forwarding_config.touch(mode=0o600, exist_ok=False)
        forwarding_config.write_text(rendered)
        os.chmod(forwarding_config, 0o600)
        api_template = (Path(__file__).resolve().parent / "api-audit-fluent-bit.yaml").read_text()
        api_rendered = api_template.replace("__SINK_USER__", json.dumps(SINK_ACTOR))
        api_rendered = api_rendered.replace("__SINK_PASSWORD__", json.dumps(valid_password))
        api_forwarding_config = root / "api-audit-fluent-bit.yaml"
        api_forwarding_config.touch(mode=0o600, exist_ok=False)
        api_forwarding_config.write_text(api_rendered)
        os.chmod(api_forwarding_config, 0o600)
        yield {"ca_cert": ca_cert, "sink_cert": sink_cert, "sink_key": sink_key,
               "username": username, "password": password, "wrong_password": wrong_password,
               "forwarding_config": forwarding_config,
               "api_forwarding_config": api_forwarding_config}
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise RuntimeError("temporary fixture sink identity/TLS generation failed") from None
    finally:
        temporary.cleanup()


def _wait(lab, name):
    lab.kubectl("rollout", "status", f"deployment/{name}", "--timeout=90s", timeout=100)


def _fixture_identity(lab):
    auth = lab.kubeconfig.parent / "registry-auth"
    auth.mkdir(mode=0o700)
    entries = []
    for actor, filename in ((ACTOR, "password"), (ADMIN_ACTOR, "admin-password")):
        password = secrets.token_urlsafe(24)
        result = subprocess.run(("htpasswd", "-Bni", actor), input=password + "\n",
                                text=True, capture_output=True, timeout=15, env=lab.env)
        if result.returncode or not result.stdout.startswith(actor + ":"):
            lab.block("Could not prepare the disposable registry identity")
        entries.append(result.stdout)
        path = auth / filename
        path.touch(mode=0o600, exist_ok=False)
        path.write_text(password)
    htpasswd = auth / "htpasswd"
    htpasswd.touch(mode=0o600, exist_ok=False)
    htpasswd.write_text("".join(entries))
    lab.kubectl("create", "secret", "generic", "registry-auth",
                f"--from-file=htpasswd={htpasswd}", f"--from-file=password={auth/'password'}",
                f"--from-file=admin-password={auth/'admin-password'}")


def _setup(lab):
    _fixture_identity(lab)
    with _temporary_forwarding_material() as material:
        _configmap(lab, "sink-ca", {"ca.pem": material["ca_cert"].read_text()})
        lab.kubectl("create", "secret", "tls", "sink-tls", "--cert", str(material["sink_cert"]),
                    "--key", str(material["sink_key"]))
        lab.kubectl("create", "secret", "generic", "sink-auth",
                    f"--from-file=username={material['username']}",
                    f"--from-file=password={material['password']}")
        lab.kubectl("create", "secret", "generic", "sink-wrong-auth",
                    f"--from-file=username={material['username']}",
                    f"--from-file=password={material['wrong_password']}")
        lab.kubectl("create", "secret", "generic", "forwarding-config",
                    f"--from-file=fluent-bit.yaml={material['forwarding_config']}")
        lab.kubectl("create", "secret", "generic", "api-audit-forwarding-config",
                    f"--from-file=fluent-bit.yaml={material['api_forwarding_config']}")
    config = {"distSpecVersion": "1.1.0", "storage": {"rootDirectory": "/var/lib/registry"},
              "log": {"level": "info", "output": ACCESS, "audit": AUDIT},
              "extensions": {"trust": {"enable": True, "cosign": True}},
              "http": {"address": "0.0.0.0", "port": "5000",
                       "auth": {"htpasswd": {"path": "/auth/htpasswd"}},
                       "accessControl": {"adminPolicy": {"users": [ADMIN_ACTOR], "actions": ["create"]},
                                         "repositories": {REPO: {"policies": [
                           {"users": [ACTOR], "actions": ["read", "create", "update", "delete"]}
                       ]}}}}}
    _configmap(lab, "registry-config", {"config.json": json.dumps(config)})
    lab.kubectl("create", "configmap", "cosign-public-key",
                f"--from-file=public.pem={HERE / 'cosign-public.pem'}")
    _configmap(lab, "scripts", {name: (HERE / name).read_text() for name in
                                 ("sink.py", "probe.py", "read_sink.py", "read_k8s_audit.py",
                                  "sink_auth_probe.py",
                                  "admin_event_probe.py", "config_read_probe.py")})
    _submit(lab, {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                  "metadata": {"name": "sink-data"},
                  "spec": {"accessModes": ["ReadWriteOnce"],
                           "resources": {"requests": {"storage": "64Mi"}}}})
    _submit(lab, {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                  "metadata": {"name": "registry-data"},
                  "spec": {"accessModes": ["ReadWriteOnce"],
                           "resources": {"requests": {"storage": "64Mi"}}}})
    scripts = _volume("scripts", configMap={"name": "scripts"})
    script_mount = _mount("scripts", "/app", read_only=True)
    _deployment(lab, "sink", [_container("sink", PYTHON, [script_mount, _mount("data", "/sink"),
                                        _mount("tls", "/tls", read_only=True),
                                        _mount("sink-auth", "/sink-auth", read_only=True)],
                                        command=["python", "/app/sink.py"], ready_port=8443)],
                [scripts, _volume("data", persistentVolumeClaim={"claimName": "sink-data"}),
                 _volume("tls", secret={"secretName": "sink-tls", "defaultMode": 0o440}),
                 _volume("sink-auth", secret={"secretName": "sink-auth", "defaultMode": 0o440})], 8443)
    _deployment(lab, "probe", [_container("probe", PYTHON, [script_mount,
                                          _mount("auth", "/auth", read_only=True),
                                          _mount("sink-auth", "/sink-auth", read_only=True),
                                          _mount("sink-wrong-auth", "/sink-wrong-auth", read_only=True),
                                          _mount("sink-ca", "/sink-ca", read_only=True),
                                          _mount("cosign-key", "/cosign", read_only=True)],
                                          command=["python", "-c", "import time; time.sleep(3600)"])],
                [scripts, _volume("auth", secret={"secretName": "registry-auth",
                                                  "items": [{"key": "password", "path": "password"},
                                                            {"key": "admin-password", "path": "admin-password"}]}),
                 _volume("sink-auth", secret={"secretName": "sink-auth", "defaultMode": 0o440}),
                 _volume("sink-wrong-auth", secret={"secretName": "sink-wrong-auth", "defaultMode": 0o440}),
                 _volume("sink-ca", configMap={"name": "sink-ca"}),
                 _volume("cosign-key", configMap={"name": "cosign-public-key"})])
    for registry in ("without-forwarding", "with-forwarding"):
        read_events = _mount("events", "/events", read_only=True)
        config_volume = _volume("config", configMap={"name": "registry-config"})
        volumes = [config_volume,
                   _volume("auth", secret={"secretName": "registry-auth",
                                           "items": [{"key": "htpasswd", "path": "htpasswd"}]}),
                   (_volume("registry", persistentVolumeClaim={"claimName": "registry-data"})
                    if registry == "with-forwarding" else _volume("registry", emptyDir={})),
                   _volume("events", emptyDir={})]
        containers = [
            _container("zot", ZOT, [_mount("config", "/etc/zot", read_only=True),
                                   _mount("auth", "/auth", read_only=True),
                                   _mount("registry", "/var/lib/registry"), _mount("events", "/events")],
                       args=["serve", "/etc/zot/config.json"], ready_port=5000),
            _container("observer", BUSYBOX,
                       [read_events, _mount("config", "/config", read_only=True)],
                       command=["sleep", "3600"]),
        ]
        if registry == "with-forwarding":
            volumes.extend([_volume("forwarding", secret={"secretName": "forwarding-config",
                                                          "defaultMode": 0o440}),
                            _volume("sink-auth", secret={"secretName": "sink-auth", "defaultMode": 0o440}),
                            _volume("sink-ca", configMap={"name": "sink-ca"})])
            containers.append(_container("fluent-bit", FLUENT_BIT,
                                         [read_events, _mount("forwarding", "/config", read_only=True),
                                          _mount("sink-ca", "/sink-ca", read_only=True)],
                                         args=["-c", "/config/fluent-bit.yaml"]))
        _deployment(lab, registry, containers, volumes, 5000)
    for name in ("sink", "probe", "without-forwarding", "with-forwarding"):
        _wait(lab, name)


def _exercise(lab, registry, tag):
    response = lab.kubectl("exec", "deployment/probe", "--", "python", "/app/probe.py",
                           f"http://{registry}:5000", tag)
    row = json.loads(response.stdout)
    expected = {"publish_status": 201, "pull_status": 200, "retag_status": 201, "delete_status": 202}
    if not all(row.get(key) == value for key, value in expected.items()) or row["pull_digest"] != row["digest"]:
        lab.block(f"OCI probe did not perform all expected operations: {row}")
    return row


def _rows(raw):
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def _selected(events, stream, targets):
    fields = ("action", "object", "status", "subject", "HTTP API Audit") if stream == "audit" else (
        "method", "path", "statusCode", "username", "HTTP API")
    method, path, status, actor, message = fields
    return [{"stream": stream, "method": row[method], "path": row[path], "status": row[status],
             "actor": row.get(actor), "time": row.get("time")} for row in events
            if row.get("message") == message and (row.get(method), row.get(path)) in targets]


def _local(lab, registry, targets):
    observed = []
    for stream, path in (("audit", AUDIT), ("access", ACCESS)):
        result = lab.kubectl("exec", f"deployment/{registry}", "-c", "observer", "--", "cat", path)
        observed.extend(_selected(_rows(result.stdout), stream, targets))
    return observed


def _read_sink(lab, targets):
    raw = lab.kubectl("exec", "deployment/probe", "--", "python", "/app/read_sink.py",
                      "https://sink.saf-test.svc.cluster.local:8443/events")
    rows = _rows(raw.stdout)
    return [entry for stream in ("audit", "access")
            for entry in _selected([row["event"] for row in rows if row["stream"] == stream], stream, targets)]


def _expected(tag, digest):
    prefix = f"/v2/{REPO}/manifests"
    operations = [("PUT", f"{prefix}/{tag}-v1", 201), ("GET", f"{prefix}/{tag}-v1", 200),
                  ("PUT", f"{prefix}/{tag}-v2", 201), ("DELETE", f"{prefix}/{digest}", 202)]
    expected = [(stream, method, path, status, ACTOR) for stream in ("audit", "access")
                for method, path, status in operations if stream == "access" or method != "GET"]
    return Counter(expected), {(method, path) for method, path, _ in operations}


def _count(events, *, timestamp=False):
    keys = ("stream", "method", "path", "status", "actor")
    if timestamp:
        keys += ("time",)
    return Counter(tuple(row[key] for key in keys) for row in events)


def _await_corpus(lab, targets, expected):
    start = time.monotonic()
    while time.monotonic() - start < 35:
        delivered = _read_sink(lab, targets)
        if _count(delivered, timestamp=True) == _count(expected, timestamp=True):
            return delivered
        time.sleep(0.6)
    return delivered


def _admin_event_records(rows):
    return [row for row in rows if
            (row["stream"] == "audit" and row["method"] == "POST" and row["path"] == ADMIN_PATH
             and row["status"] == 200 and row["actor"] == ADMIN_ACTOR)
            or (row["stream"] == "access" and row["method"] == "POST" and row["path"] == ADMIN_PATH
                and ((row["status"] == 403 and row["actor"] == ACTOR)
                     or (row["status"] == 200 and row["actor"] == ADMIN_ACTOR)))]


def _await_admin_events(lab, expected):
    targets = {("POST", ADMIN_PATH)}
    start = time.monotonic()
    while time.monotonic() - start < 35:
        received = _admin_event_records(_read_sink(lab, targets))
        if _count(received, timestamp=True) == _count(expected, timestamp=True):
            return received
        time.sleep(0.6)
    return received


def verify_one_503_retry(lab):
    tag = "retry-503"
    started = time.monotonic()
    probe = json.loads(lab.kubectl("exec", "deployment/probe", "--", "python", "/app/probe.py",
                                   "http://with-forwarding:5000", tag).stdout)
    marker = {("PUT", RETRY_PATH)}
    local = _local(lab, "with-forwarding", marker)
    local_access = [row for row in local if row["stream"] == "access"]
    received = _await_corpus(lab, marker, local)
    received_access = [row for row in received if row["stream"] == "access"]
    retry_state = json.loads(lab.kubectl(
        "exec", "deployment/probe", "--", "python", "/app/read_sink.py",
        "https://sink.saf-test.svc.cluster.local:8443/retry-state").stdout)
    failed_hashes = retry_state.get("rejected_body_sha256", [])
    accepted_hashes = retry_state.get("accepted_body_sha256", [])
    recovered_same_chunk = (len(failed_hashes) == 1 and len(accepted_hashes) == 1
                            and failed_hashes[0] == accepted_hashes[0])
    source_received_match = (_count(local_access, timestamp=True)
                             == _count(received_access, timestamp=True)
                             and len(local_access) == 1 and len(received_access) == 1)
    ok = (probe.get("publish_status") == 201 and probe.get("pull_status") == 200
          and probe.get("retag_status") == 201 and probe.get("delete_status") == 202
          and retry_state.get("rejected_attempts") == 1
          and retry_state.get("accepted_attempts") == 1
          and retry_state.get("rejected_marker_records") == 1
          and retry_state.get("accepted_marker_records") == 1
          and recovered_same_chunk and source_received_match)
    observation = {
        "fixed_registry_sequence_succeeded": bool(
            probe.get("publish_status") == 201 and probe.get("pull_status") == 200
            and probe.get("retag_status") == 201 and probe.get("delete_status") == 202),
        "source_marker_records": len(local_access),
        "sink_marker_records": len(received_access),
        "source_sink_marker_identity_matches": source_received_match,
        "authenticated_precommit_503_count": retry_state.get("rejected_attempts") == 1,
        "post_503_accepted_marker_count": retry_state.get("accepted_marker_records") == 1,
        "same_request_body_retried": recovered_same_chunk,
    }
    evidence = {
        "observed": observation,
        "exact_source_access_events": local_access,
        "exact_delivered_access_events": received_access,
        "rejected_body_sha256": failed_hashes,
        "accepted_body_sha256": accepted_hashes,
        "rejected_attempts": retry_state.get("rejected_attempts"),
        "accepted_attempts": retry_state.get("accepted_attempts"),
        "rejected_marker_records": retry_state.get("rejected_marker_records"),
        "accepted_marker_records": retry_state.get("accepted_marker_records"),
        "case_elapsed_seconds": time.monotonic() - started,
    }
    (lab.evidence / "bounded-forwarding-retry.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    lab.check("retry", "Fluent Bit retries one rejected authenticated registry access batch and the exact marker is committed once",
              ok, observation)


def _sink_uid(lab):
    raw = lab.kubectl("get", "pods", "-l", "app=sink", "-o", "json")
    pod, = json.loads(raw.stdout)["items"]
    return pod["metadata"]["uid"]


def _effective_audit_user(event):
    return (event.get("impersonatedUser") or event.get("user") or {}).get("username")


def _config_owner_events(lab):
    if not lab.audit_file.is_file():
        return []
    selected = []
    for line in lab.audit_file.read_text().splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        ref = event.get("objectRef", {})
        if (event.get("level") == "Metadata" and event.get("stage") == "ResponseComplete"
                and event.get("verb") in {"patch", "update"}
                and ref.get("namespace") == NAMESPACE and ref.get("resource") == "configmaps"
                and ref.get("name") == "registry-config"):
            selected.append(event)
    return selected


def _forward_authoritative_audit_event(lab, event):
    """Forward exactly one approved Metadata event through a read-only projection."""
    def finish(matched, observation, raw):
        (lab.evidence / "forwarded-config-owner-audit-event.json").write_text(
            json.dumps(raw, indent=2, sort_keys=True) + "\n")
        lab.check("config-owner-forwarded",
                  "The exact authorized Kubernetes Metadata audit event reaches the protected central sink",
                  matched, observation)
        return observation

    ref = event.get("objectRef", {}) if isinstance(event, dict) else {}
    source_valid = (isinstance(event, dict) and bool(event.get("auditID"))
                    and _effective_audit_user(event) == CONFIG_OWNER
                    and event.get("apiVersion") == "audit.k8s.io/v1"
                    and event.get("kind") == "Event"
                    and event.get("level") == "Metadata"
                    and event.get("verb") == "patch"
                    and event.get("stage") == "ResponseComplete"
                    and ref.get("namespace") == NAMESPACE
                    and ref.get("apiGroup", "") == ""
                    and ref.get("resource") == "configmaps"
                    and ref.get("name") == "registry-config"
                    and event.get("responseStatus", {}).get("code") == 200
                    and event.get("requestObject") is None
                    and event.get("responseObject") is None)
    if not source_valid:
        observation = {
            "source_metadata_event_valid": False,
            "source_projection_records": 0,
            "source_projection_bytes_bounded": False,
            "effective_config_owner_matches": False,
            "metadata_request_and_response_absent": False,
            "sink_api_audit_records": 0,
            "same_audit_id_at_sink": False,
            "source_sink_event_digest_matches": False,
            "no_unrelated_api_records_forwarded": False,
        }
        return finish(False, observation, {"source_event_valid": False})

    source_digest = hashlib.sha256(json.dumps(
        event, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    source_user = event.get("impersonatedUser") or event.get("user") or {}
    source_ref = event["objectRef"]
    projection_event = {
        "apiVersion": event["apiVersion"],
        "kind": event["kind"],
        "level": event["level"],
        "auditID": event["auditID"],
        "stage": event["stage"],
        "stageTimestamp": event.get("stageTimestamp"),
        "verb": event["verb"],
        "effectiveUsername": source_user.get("username"),
        "objectRef": {key: source_ref.get(key) for key in
                      ("apiGroup", "apiVersion", "resource", "namespace", "name")},
        "responseStatus": {"code": event["responseStatus"]["code"]},
        "source": "case-owned-kube-apiserver-audit-metadata",
    }
    projection_digest = hashlib.sha256(json.dumps(
        projection_event, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    projection = json.dumps(projection_event, sort_keys=True, separators=(",", ":")) + "\n"
    baseline = json.loads(lab.kubectl("exec", "deployment/probe", "--", "python",
                                      "/app/read_k8s_audit.py", event["auditID"], projection_digest,
                                      timeout=10).stdout)
    baseline_empty = (baseline.get("sink_api_audit_record_count") == 0
                      and baseline.get("matching_audit_ids") == [])
    with tempfile.TemporaryDirectory(prefix="saf-0905-040-api-audit-projection-") as directory:
        os.chmod(directory, 0o700)
        event_file = Path(directory) / "audit.jsonl"
        event_file.touch(mode=0o600, exist_ok=False)
        event_file.write_text(projection, encoding="utf-8")
        os.chmod(event_file, 0o600)
        if event_file.read_text(encoding="utf-8") != projection:
            lab.block("The one-record API audit projection changed before ConfigMap creation")
        if len(event_file.read_bytes().splitlines()) != 1 or event_file.stat().st_size > 65536:
            lab.block("The API audit projection exceeded its one-record size bound")
        # File-path input avoids placing the metadata record in the runner's command log.
        lab.kubectl("create", "configmap", "api-audit-event",
                    f"--from-file=audit.jsonl={event_file}")
        lab.kubectl("patch", "configmap/api-audit-event", "--type=merge",
                    "-p", '{"immutable":true}')

    volumes = [
        _volume("config", secret={"secretName": "api-audit-forwarding-config",
                                  "defaultMode": 0o440}),
        _volume("audit-event", configMap={"name": "api-audit-event"}),
        _volume("sink-ca", configMap={"name": "sink-ca"}),
    ]
    container = _container("fluent-bit", FLUENT_BIT,
                           [_mount("config", "/config", read_only=True),
                            _mount("audit-event", "/audit-event", read_only=True),
                            _mount("sink-ca", "/sink-ca", read_only=True)],
                           args=["-c", "/config/fluent-bit.yaml"])
    _deployment(lab, "api-audit-forwarder", [container], volumes)
    _wait(lab, "api-audit-forwarder")

    start = time.monotonic()
    deadline = start + 35
    delivery = {"sink_api_audit_record_count": 0, "matching_audit_ids": [],
                "matching_event_sha256": [], "expected_event_sha256_matches": False}
    while deadline - time.monotonic() >= 10:
        result = lab.kubectl("exec", "deployment/probe", "--", "python",
                             "/app/read_k8s_audit.py", event["auditID"], projection_digest,
                             timeout=10)
        delivery = json.loads(result.stdout)
        if delivery.get("sink_api_audit_record_count") == 1:
            break
        time.sleep(0.5)

    received_ids = delivery.get("matching_audit_ids", [])
    received_digests = delivery.get("matching_event_sha256", [])
    received_metadata = delivery.get("matching_metadata", [])
    exact_identity = received_ids == [event["auditID"]]
    source_sink_metadata_matches = received_metadata == [projection_event]
    digest_matches = (received_digests == [projection_digest]
                      and delivery.get("expected_event_sha256_matches") is True)
    no_unrelated_rows = delivery.get("sink_api_audit_record_count") == 1
    observation = {
        "source_metadata_event_valid": True,
        "source_projection_records": 1,
        "source_projection_bytes_bounded": True,
        "effective_config_owner_matches": _effective_audit_user(event) == CONFIG_OWNER,
        "metadata_request_and_response_absent": (event.get("requestObject") is None
                                                   and event.get("responseObject") is None),
        "sink_api_audit_records_before": baseline.get("sink_api_audit_record_count", 0),
        "audit_id_absent_before_forwarding": baseline_empty,
        "sink_api_audit_records": delivery.get("sink_api_audit_record_count", 0),
        "same_audit_id_at_sink": exact_identity,
        "source_sink_metadata_fields_match": source_sink_metadata_matches,
        "source_sink_event_digest_matches": digest_matches,
        "no_unrelated_api_records_forwarded": no_unrelated_rows,
    }
    raw = {
        "source_audit_id": event["auditID"],
        "baseline_sink_api_audit_record_count": baseline.get("sink_api_audit_record_count", 0),
        "baseline_matching_audit_ids": baseline.get("matching_audit_ids", []),
        "sink_matching_audit_ids": received_ids,
        "source_event_sha256": source_digest,
        "projected_event_sha256": projection_digest,
        "sink_matching_event_sha256": received_digests,
        "source_metadata": projection_event,
        "sink_matching_metadata": received_metadata,
        "source_projection_record_count": 1,
        "sink_api_audit_record_count": delivery.get("sink_api_audit_record_count", 0),
        "receipt_poll_within_35s": time.monotonic() < deadline,
    }
    matched = (baseline_empty and exact_identity and source_sink_metadata_matches and digest_matches
               and no_unrelated_rows)
    return finish(matched, observation, raw)


def _read_count(rows, status, path):
    return sum(row["stream"] == "access" and row["method"] == "GET" and row["path"] == path
               and row["status"] == status and row["actor"] == ACTOR for row in rows)


def verify_config_owner_change(lab):
    tag = "permission-change"
    registry = "http://with-forwarding:5000"
    seeded = json.loads(lab.kubectl("exec", "deployment/probe", "--", "python", "/app/probe.py",
                                     registry, tag, "seed").stdout)
    if seeded.get("publish_status") != 201 or not seeded.get("digest", "").startswith("sha256:"):
        lab.block("The owned authorization comparison manifest was not seeded")
    reference, expected_digest = f"{tag}-v1", seeded["digest"]

    # Scope the owner to the named ConfigMap, including kubectl patch's preliminary GET.
    _submit(lab, {"apiVersion": "v1", "kind": "ServiceAccount",
                  "metadata": {"name": "registry-config-owner"}})
    _submit(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                  "metadata": {"name": "registry-config-owner"},
                  "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                             "resourceNames": ["registry-config"], "verbs": ["get", "patch"]}]})
    _submit(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                  "metadata": {"name": "registry-config-owner"},
                  "subjects": [{"kind": "ServiceAccount", "name": "registry-config-owner",
                                "namespace": NAMESPACE}],
                  "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                              "name": "registry-config-owner"}})

    before_object = json.loads(lab.kubectl("get", "configmap/registry-config", "-o", "json").stdout)
    config_before = json.loads(before_object["data"]["config.json"])
    policy_before = config_before["http"]["accessControl"]["repositories"][REPO]
    policy_before_hash = hashlib.sha256(json.dumps(policy_before, sort_keys=True,
                                                   separators=(",", ":")).encode()).hexdigest()
    config_json = before_object["data"]["config.json"]
    config_projection_hash = hashlib.sha256(config_json.encode()).hexdigest()
    read_path = f"/v2/{REPO}/manifests/{reference}"
    access_targets = {("GET", read_path)}
    local_before = _local(lab, "with-forwarding", access_targets)

    allowed = json.loads(lab.kubectl("exec", "deployment/probe", "--", "python", "/app/config_read_probe.py",
                                     registry, reference, expected_digest).stdout)
    local_after_allowed = _local(lab, "with-forwarding", access_targets)
    allowed_recorded_once = (_read_count(local_after_allowed, 200, read_path)
                             - _read_count(local_before, 200, read_path) == 1)

    config_after = json.loads(before_object["data"]["config.json"])
    config_after["http"]["accessControl"]["repositories"][REPO]["policies"][0]["users"] = [
        "fixture-alternate-owner"
    ]
    config_after_json = json.dumps(config_after, separators=(",", ":"))
    policy_after = config_after["http"]["accessControl"]["repositories"][REPO]
    policy_after_hash = hashlib.sha256(json.dumps(policy_after, sort_keys=True,
                                                  separators=(",", ":")).encode()).hexdigest()
    patch = json.dumps({"data": {"config.json": config_after_json}}, separators=(",", ":"))
    lab.kubectl("patch", "configmap/registry-config", "--type=merge", "-p", patch,
                f"--as={CONFIG_OWNER}")
    after_object = json.loads(lab.kubectl("get", "configmap/registry-config", "-o", "json").stdout)
    # Bind observed behavior to a controlled reload of the exact mounted revisions.
    allowed_forwarded = _count(_await_corpus(lab, access_targets, local_after_allowed), timestamp=True)
    before_restart = _count(local_after_allowed, timestamp=True)
    def ready_pod_uid():
        result = lab.kubectl("get", "pods", "-l", "app=with-forwarding", "-o", "json")
        pods = [pod for pod in json.loads(result.stdout)["items"]
                if any(c.get("type") == "Ready" and c.get("status") == "True"
                       for c in pod.get("status", {}).get("conditions", []))
                and not pod["metadata"].get("deletionTimestamp")]
        if len(pods) != 1:
            lab.block("Expected one ready owned registry Pod")
        return pods[0]["metadata"]["uid"]

    previous_pod = ready_pod_uid()
    lab.kubectl("rollout", "restart", "deployment/with-forwarding")
    _wait(lab, "with-forwarding")
    registry_replaced = ready_pod_uid() != previous_pod

    # Wait for the projected ConfigMap to expose the exact revised bytes before one denied app read.
    expected_projection = hashlib.sha256(config_after_json.encode()).hexdigest()
    projected = None
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        result = lab.kubectl("exec", "deployment/with-forwarding", "-c", "observer", "--",
                             "sha256sum", "/config/config.json")
        projected = result.stdout.split()[0] if result.stdout.split() else None
        if projected == expected_projection:
            break
        time.sleep(0.25)
    if projected != expected_projection:
        lab.block("The updated registry ConfigMap was not projected to the owned Zot Pod")

    denied = json.loads(lab.kubectl("exec", "deployment/probe", "--", "python", "/app/config_read_probe.py",
                                    registry, reference, expected_digest).stdout)
    local_after_denied = _local(lab, "with-forwarding", access_targets)
    denied_recorded_once = (_read_count(local_after_denied, 403, read_path) == 1
                           and _read_count(local_after_denied, 200, read_path) == 0)

    events = _config_owner_events(lab)
    event, = events if len(events) == 1 else (None,)
    audit_match = (event is not None and event.get("verb") == "patch"
                   and _effective_audit_user(event) == CONFIG_OWNER
                   and event.get("responseStatus", {}).get("code") == 200
                   and event.get("auditID")
                   and event.get("requestObject") is None and event.get("responseObject") is None)
    ok = (before_object["metadata"]["uid"] == after_object["metadata"]["uid"]
          and before_object["metadata"]["resourceVersion"] != after_object["metadata"]["resourceVersion"]
          and config_projection_hash != expected_projection and policy_before_hash != policy_after_hash
          and allowed == {"status": 200, "digest_matches": True} and allowed_recorded_once
          and denied == {"status": 403, "digest_matches": False} and denied_recorded_once
          and audit_match and registry_replaced)
    receipt = {
        "config_owner_effective_identity": _effective_audit_user(event) if event else None,
        "audit_id": event.get("auditID") if event else None,
        "audit_stage_timestamp": event.get("stageTimestamp") if event else None,
        "metadata_audit_events_for_named_configmap": len(events),
        "audit_verb": event.get("verb") if event else None,
        "audit_status": event.get("responseStatus", {}).get("code") if event else None,
        "audit_metadata_only": bool(event and event.get("requestObject") is None
                                     and event.get("responseObject") is None),
        "audit_id_present": bool(event and event.get("auditID")),
        "config_uid_stable": before_object["metadata"]["uid"] == after_object["metadata"]["uid"],
        "config_uid": before_object["metadata"]["uid"],
        "config_resource_version_before": before_object["metadata"]["resourceVersion"],
        "config_resource_version_after": after_object["metadata"]["resourceVersion"],
        "resource_version_advanced": before_object["metadata"]["resourceVersion"]
                                     != after_object["metadata"]["resourceVersion"],
        "config_sha256_before": config_projection_hash,
        "config_sha256_after": expected_projection,
        "config_sha256_changed": config_projection_hash != expected_projection,
        "policy_projection_sha256_before": policy_before_hash,
        "policy_projection_sha256_after": policy_after_hash,
        "policy_projection_sha256_changed": policy_before_hash != policy_after_hash,
        "projected_config_sha256_matches": projected == expected_projection,
        "registry_pod_replaced": registry_replaced,
        "allowed_read_status": allowed["status"],
        "allowed_marker_digest_matches": allowed["digest_matches"],
        "allowed_access_record_count": int(allowed_recorded_once),
        "denied_read_status": denied["status"],
        "denied_marker_digest_matches": denied["digest_matches"],
        "denied_access_record_count": int(denied_recorded_once),
        "native_zot_policy_change_event_claimed": False,
    }
    (lab.evidence / "zot-config-owner-change.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    combined = local_after_allowed + local_after_denied
    operations_are_forwarded = (allowed_forwarded == before_restart and _count(
        _await_corpus(lab, access_targets, combined), timestamp=True
    ) == _count(combined, timestamp=True))
    stable_evidence = {key: receipt[key] for key in (
        "config_owner_effective_identity", "metadata_audit_events_for_named_configmap", "audit_verb",
        "audit_status", "audit_metadata_only", "audit_id_present", "config_uid_stable",
        "resource_version_advanced", "config_sha256_changed", "policy_projection_sha256_changed",
        "projected_config_sha256_matches", "registry_pod_replaced", "allowed_read_status",
        "allowed_marker_digest_matches",
        "allowed_access_record_count", "denied_read_status", "denied_marker_digest_matches",
        "denied_access_record_count", "native_zot_policy_change_event_claimed",
    )}
    stable_evidence["registry_access_events_forwarded"] = operations_are_forwarded
    lab.check("config-owner", "A scoped Kubernetes ConfigMap owner change is metadata-audited and changes the allowed marker read to denied",
              ok and operations_are_forwarded, stable_evidence)
    _forward_authoritative_audit_event(lab, event)


def run(lab):
    _setup(lab)
    red = _exercise(lab, "without-forwarding", "first")
    expected, targets = _expected("first", red["digest"])
    local_red = _local(lab, "without-forwarding", targets)
    sink_red = _read_sink(lab, targets)
    lab.check("red", "Without forwarding the exact registry actions appear locally and the separate sink stays empty",
              _count(local_red) == expected and not sink_red,
              {"local_expected_records": len(local_red), "sink_records": len(sink_red)})

    green = _exercise(lab, "with-forwarding", "first")
    local_green = _local(lab, "with-forwarding", targets)
    received = _await_corpus(lab, targets, local_green)
    lab.check("green", "Fluent Bit delivers the exact local audit and HTTP access records for each action",
              green == red and _count(local_green) == expected and all(row["time"] for row in local_green)
              and _count(received, timestamp=True) == _count(local_green, timestamp=True),
              {"expected_audit_records": 3, "expected_access_records": 4,
               "exact_corpus_matches": _count(received, timestamp=True) == _count(local_green, timestamp=True)})

    old_uid = _sink_uid(lab)
    lab.kubectl("delete", "pod", "-l", "app=sink", "--wait=true", timeout=70)
    _wait(lab, "sink")
    new_uid = _sink_uid(lab)
    retained = _read_sink(lab, targets)
    after = _exercise(lab, "with-forwarding", "second")
    after_expected, after_targets = _expected("second", after["digest"])
    after_local = _local(lab, "with-forwarding", after_targets)
    after_received = _await_corpus(lab, after_targets, after_local)
    retained_exact = _count(retained, timestamp=True) == _count(received, timestamp=True)
    continued = _count(after_local) == after_expected and _count(after_received, timestamp=True) == _count(after_local, timestamp=True)
    (lab.evidence / "forwarded-zot-events.json").write_text(json.dumps(
        {"local_before": local_red, "sink_before": sink_red, "local_enabled": local_green,
         "sink_enabled": received, "retained": retained, "local_after_restart": after_local,
         "sink_after_restart": after_received, "receiver_uids": [old_uid, new_uid]}, indent=2) + "\n")
    lab.check("positive", "The replacement receiver retains prior events and accepts the exact next registry sequence",
              old_uid != new_uid and retained_exact and continued,
              {"receiver_replaced": old_uid != new_uid, "prior_records_exact": retained_exact,
               "new_records_exact": continued})

    auth_probe = lab.kubectl("exec", "deployment/probe", "--", "python", "/app/sink_auth_probe.py",
                             "https://sink.saf-test.svc.cluster.local:8443/audit")
    auth_result = json.loads(auth_probe.stdout)
    auth_ok = auth_result == {"unauthorized_rejected": True, "status": 401}
    lab.check("identity", "The local central receiver requires its synthetic forwarding credential",
              auth_ok, auth_result)

    admin_probe = lab.kubectl("exec", "deployment/probe", "--", "python", "/app/admin_event_probe.py")
    admin_result = json.loads(admin_probe.stdout)
    targets = {("POST", ADMIN_PATH)}
    local_admin = _admin_event_records(_local(lab, "with-forwarding", targets))
    expected_admin_shape = {
        ("audit", "POST", ADMIN_PATH, 200, ADMIN_ACTOR): 1,
        ("access", "POST", ADMIN_PATH, 403, ACTOR): 1,
        ("access", "POST", ADMIN_PATH, 200, ADMIN_ACTOR): 1,
    }
    observed_admin_shape = Counter((row["stream"], row["method"], row["path"], row["status"], row["actor"])
                                  for row in local_admin)
    forwarded_admin = _await_admin_events(lab, local_admin)
    admin_event_ok = (admin_result == {"admin_allowed": True, "admin_status": 200,
                                      "non_admin_denied": True, "non_admin_status": 403}
                      and all(row["time"] for row in local_admin)
                      and observed_admin_shape == Counter(expected_admin_shape)
                      and _count(forwarded_admin, timestamp=True) == _count(local_admin, timestamp=True))
    safe_admin = {"probe": admin_result,
                  "local_native_audit_admin_success_count": sum(
                      row["stream"] == "audit" and row["actor"] == ADMIN_ACTOR and row["status"] == 200
                      for row in local_admin),
                  "local_access_denial_count": sum(
                      row["stream"] == "access" and row["actor"] == ACTOR and row["status"] == 403
                      for row in local_admin),
                  "local_access_admin_success_count": sum(
                      row["stream"] == "access" and row["actor"] == ADMIN_ACTOR and row["status"] == 200
                      for row in local_admin),
                  "forwarded_exactly": _count(forwarded_admin, timestamp=True)
                  == _count(local_admin, timestamp=True)}
    (lab.evidence / "admin-event-forwarding.json").write_text(json.dumps(safe_admin, indent=2, sort_keys=True) + "\n")
    lab.check("admin-event", "The permitted Zot trust-key administration is attributed in native audit and access records and forwarded exactly",
              admin_event_ok, safe_admin)

    verify_one_503_retry(lab)
    verify_config_owner_change(lab)
