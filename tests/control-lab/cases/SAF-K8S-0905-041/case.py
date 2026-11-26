"""Downstream normalized registry-event alert and review fixture."""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
import os

HERE = Path(__file__).resolve().parent
PORT = 8080
PYTHON_IMAGE = (
    "docker.io/library/python:3.13.2-alpine@sha256:"
    "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
)
ZOT_IMAGE = (
    "ghcr.io/project-zot/zot:v2.1.23@sha256:"
    "9d3de83ac2099e6f4843045b4c9b65b7e8baf40f92d28f54906dee9d4d390fd7"
)
BUSYBOX_IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
REVIEW = "registry-alert-audit-003"
REGISTRY = "zot-source"
REGISTRY_REPO = "saf-test/model-a"
REGISTRY_TAG = "alert-marker-v1"
REGISTRY_PATH = f"/v2/{REGISTRY_REPO}/manifests/{REGISTRY_TAG}"
REGISTRY_AUDIT = "/audit/events.jsonl"
REGISTRY_ACTOR = "fixture-publisher"
SCOPE = (
    "A disposable Kind cluster runs a case-owned monitor against fixed normalized events and one actual Zot v2.1.23 "
    "native audit event for a case-owned empty OCI marker. It evaluates bounded sensitive-operation and supplied "
    "anomaly rules, rejects wrong source labels, suppresses replay duplicates, and sends alert projections to an "
    "authenticated case-local HTTPS receiver using fixture-only Basic authentication. Kubernetes RBAC restricts "
    "writing one named analyst disposition. "
    "This does not establish authenticated production event forwarding, provider completeness beyond this one Zot "
    "operation, general anomaly detection, a human decision, deployed reviewer identity, durable SIEM retention, or other "
    "registry provider behavior."
)


def _create(lab, resource):
    lab.kubectl("create", "-f", "-", payload=json.dumps(resource))


def _setup_receiver_security(lab):
    """Create short-lived TLS/auth material; kubectl receives file paths, never values."""
    try:
        with tempfile.TemporaryDirectory(prefix="saf-0905-041-receiver-",
                                         dir=lab.kubeconfig.parent) as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            ca_key, ca_csr, ca_cert = root / "ca.key", root / "ca.csr", root / "ca.pem"
            leaf_key, leaf_csr, leaf_cert = root / "receiver.key", root / "receiver.csr", root / "receiver.crt"
            ca_ext, leaf_ext = root / "ca.ext", root / "receiver.ext"
            username, password, wrong = root / "username", root / "password", root / "wrong-password"
            dns = "audit-alert-receiver.saf-test.svc.cluster.local"
            ca_ext.write_text("basicConstraints=critical,CA:TRUE,pathlen:0\n"
                              "keyUsage=critical,keyCertSign,cRLSign\n"
                              "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\n")
            leaf_ext.write_text("basicConstraints=critical,CA:FALSE\n"
                                "keyUsage=critical,digitalSignature,keyEncipherment\n"
                                "extendedKeyUsage=serverAuth\n"
                                f"subjectAltName=DNS:{dns}\n"
                                "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
            username.write_text("fixture-alert-forwarder\n")
            valid = secrets.token_urlsafe(24)
            invalid = secrets.token_urlsafe(24)
            while invalid == valid:
                invalid = secrets.token_urlsafe(24)
            password.write_text(valid + "\n")
            wrong.write_text(invalid + "\n")
            for path in (username, password, wrong, ca_ext, leaf_ext):
                os.chmod(path, 0o600)
            commands = [
                ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key),
                 "-out", str(ca_csr), "-subj", "/CN=SAF-K8S-0905-041 receiver fixture CA"],
                ["openssl", "x509", "-req", "-in", str(ca_csr), "-signkey", str(ca_key), "-days", "2",
                 "-extfile", str(ca_ext), "-out", str(ca_cert)],
                ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(leaf_key),
                 "-out", str(leaf_csr), "-subj", f"/CN={dns}"],
                ["openssl", "x509", "-req", "-in", str(leaf_csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
                 "-CAcreateserial", "-days", "2", "-extfile", str(leaf_ext), "-out", str(leaf_cert)],
            ]
            for command in commands:
                subprocess.run(command, check=True, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=20, env=lab.env)
            for path in (ca_key, leaf_key):
                os.chmod(path, 0o600)
            lab.kubectl("create", "configmap", "receiver-ca", f"--from-file=ca.pem={ca_cert}")
            lab.kubectl("create", "secret", "tls", "receiver-tls",
                        f"--cert={leaf_cert}", f"--key={leaf_key}")
            lab.kubectl("create", "secret", "generic", "receiver-auth",
                        f"--from-file=username={username}", f"--from-file=password={password}")
            lab.kubectl("create", "secret", "generic", "receiver-wrong-auth",
                        f"--from-file=username={username}", f"--from-file=password={wrong}")
    except Exception:
        lab.block("Could not prepare temporary receiver TLS/auth material (details suppressed)")


def _container(name, *, command, ports=None, mounts):
    item = {
        "name": name,
        "image": PYTHON_IMAGE,
        "imagePullPolicy": "IfNotPresent",
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
            "runAsNonRoot": True,
            "runAsUser": 65534,
            "readOnlyRootFilesystem": True,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "resources": {
            "requests": {"cpu": "15m", "memory": "32Mi"},
            "limits": {"cpu": "250m", "memory": "128Mi"},
        },
    }
    item["command"] = command
    if ports is not None:
        item["ports"] = ports
    item["volumeMounts"] = mounts
    return item


def _deployment(name, container, volumes):
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                        "fsGroup": 65534},
                    "containers": [container],
                    "volumes": volumes,
                },
            },
        },
    }


def _setup(lab):
    _setup_receiver_security(lab)
    scripts = {name: (HERE / name).read_text() for name in (
        "monitor.py", "receiver.py", "fixture.py", "events.json", "forward.py",
        "receiver_observe.py", "receiver_auth_probe.py", "zot_probe.py")}
    scripts["projected_review.py"] = (HERE / "projected_review.py").read_text()
    _create(lab, {
        "apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "audit-review-code"},
        "immutable": True, "data": scripts,
    })
    code_volume = {"name": "code", "configMap": {"name": "audit-review-code"}}
    code_mount = {"name": "code", "mountPath": "/app", "readOnly": True}

    receiver_state = {"name": "state", "emptyDir": {"medium": "Memory", "sizeLimit": "4Mi"}}
    receiver = _container("receiver", command=["python", "-B", "/app/receiver.py"],
                          ports=[{"name": "https", "containerPort": 8443}],
                          mounts=[code_mount, {"name": "state", "mountPath": "/state"},
                                  {"name": "receiver-tls", "mountPath": "/receiver-tls", "readOnly": True},
                                  {"name": "receiver-auth", "mountPath": "/receiver-auth", "readOnly": True}])
    receiver["readinessProbe"] = {"httpGet": {"path": "/health", "port": "https", "scheme": "HTTPS"}, "periodSeconds": 1}
    receiver_volumes = [code_volume, receiver_state,
                        {"name": "receiver-tls", "secret": {"secretName": "receiver-tls"}},
                        {"name": "receiver-auth", "secret": {"secretName": "receiver-auth"}}]
    _create(lab, _deployment("audit-alert-receiver", receiver, receiver_volumes))
    _create(lab, {
        "apiVersion": "v1", "kind": "Service", "metadata": {"name": "audit-alert-receiver"},
        "spec": {"selector": {"app": "audit-alert-receiver"},
                 "ports": [{"name": "https", "port": 8443, "targetPort": 8443}]},
    })

    state_volume = {"name": "state", "emptyDir": {"medium": "Memory", "sizeLimit": "8Mi"}}
    monitor = _container("monitor", command=["python", "-B", "/app/monitor.py"],
                         ports=[{"name": "http", "containerPort": PORT}],
                         mounts=[code_mount, {"name": "state", "mountPath": "/state"},
                                 {"name": "receiver-ca", "mountPath": "/receiver-ca", "readOnly": True},
                                 {"name": "receiver-auth", "mountPath": "/receiver-auth", "readOnly": True}])
    monitor["readinessProbe"] = {"httpGet": {"path": "/health", "port": "http"}, "periodSeconds": 1}
    _create(lab, _deployment("audit-monitor", monitor,
                             [code_volume, state_volume,
                              {"name": "receiver-ca", "configMap": {"name": "receiver-ca"}},
                              {"name": "receiver-auth", "secret": {"secretName": "receiver-auth"}}]))
    _create(lab, {
        "apiVersion": "v1", "kind": "Service", "metadata": {"name": "audit-monitor"},
        "spec": {"selector": {"app": "audit-monitor"},
                 "ports": [{"name": "http", "port": PORT, "targetPort": PORT}]},
    })
    _create(lab, _deployment(
        "audit-fixture",
        _container("fixture", command=["python", "-c", "import time; time.sleep(3600)"],
                   mounts=[code_mount,
                           {"name": "receiver-ca", "mountPath": "/receiver-ca", "readOnly": True},
                           {"name": "receiver-auth", "mountPath": "/receiver-auth", "readOnly": True},
                           {"name": "receiver-wrong-auth", "mountPath": "/receiver-wrong-auth", "readOnly": True}]),
        [code_volume,
         {"name": "receiver-ca", "configMap": {"name": "receiver-ca"}},
         {"name": "receiver-auth", "secret": {"secretName": "receiver-auth"}},
         {"name": "receiver-wrong-auth", "secret": {"secretName": "receiver-wrong-auth"}}],
    ))
    for name in ("audit-alert-receiver", "audit-monitor", "audit-fixture"):
        lab.kubectl("rollout", "status", f"deployment/{name}", "--timeout=90s", timeout=100)


def _json_exec(lab, argv):
    result = lab.kubectl("exec", "deployment/audit-fixture", "--", *argv)
    try:
        return json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        lab.block(f"Fixture returned invalid JSON: {exc}")


def check_events(lab, observations):
    baseline = observations["baseline"]
    enforced = observations["enforced"]
    replayed = observations["replayed"]
    events = [f"audit-{n:03d}" for n in range(1, 9)]
    expected_rules = {
        "audit-001": ("sensitive-publish", "fixture-publisher"),
        "audit-003": ("anomalous-pull", "fixture-reader"),
        "audit-004": ("sensitive-delete", "fixture-maintainer"),
        "audit-005": ("sensitive-permission-change", "fixture-maintainer"),
        "audit-006": ("sensitive-administration", "fixture-admin"),
    }
    expected = {"alert-" + event: {"event_id": event, "rule": rule,
                                    "actor": actor, "repository": "saf-test/model-a"}
                for event, (rule, actor) in expected_rules.items()}
    lab.check("red", "The inactive monitor receives all eight normalized events without alerting",
              baseline["events"] == events and baseline["alerts"] == {}
              and baseline["quiet"] == events and baseline["duplicates"] == 0,
              baseline)
    lab.check("green", "The same event corpus produces the five scoped alerts and leaves ordinary and out-of-scope events quiet",
              enforced["events"] == events and enforced["input_sha256"] == baseline["input_sha256"]
              and enforced["alerts"] == expected
              and enforced["quiet"] == ["audit-002", "audit-007", "audit-008"]
              and enforced["duplicates"] == 0,
              enforced)
    lab.check("positive", "Replay preserves exactly those alerts and a request with incorrect source metadata is rejected",
              replayed == {**enforced, "duplicates": len(events)}
              and observations["invalid_source"] == {"status": 422, "body": {"error": "invalid-event-provenance"}},
              {"replayed": replayed, "invalid_source": observations["invalid_source"]})


def review_alert(lab, alert):
    identity = alert["event_id"]
    start = {"alert_id": "alert-" + identity, "disposition": "unreviewed"}
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": REVIEW}, "data": start})
    group = "rbac.authorization.k8s.io"
    for identity, verbs in (("audit-observer", ["get"]), ("audit-analyst", ["get", "patch"])):
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": identity}})
        lab.create({"apiVersion": f"{group}/v1", "kind": "Role", "metadata": {"name": identity},
                    "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [REVIEW],
                               "verbs": verbs}]})
        lab.create({"apiVersion": f"{group}/v1", "kind": "RoleBinding", "metadata": {"name": identity},
                    "subjects": [{"kind": "ServiceAccount", "name": identity, "namespace": "saf-test"}],
                    "roleRef": {"apiGroup": group, "kind": "Role", "name": identity}})

    def get_record():
        return json.loads(lab.kubectl("get", f"configmap/{REVIEW}", "-o", "json").stdout)["data"]

    update = json.dumps({"data": {"disposition": "reviewed-benign-fixture"}})
    command = ("patch", f"configmap/{REVIEW}", "--type=merge", "-p", update, "-o", "json")
    denied = lab.kubectl(*command, "--as=system:serviceaccount:saf-test:audit-observer", allow_failure=True)
    forbidden = denied.returncode != 0 and "Forbidden" in denied.stderr and 'cannot patch resource "configmaps"' in denied.stderr
    unchanged = get_record() == start
    lab.check("green", "The ordinary Kubernetes account cannot change the existing alert disposition",
              forbidden and unchanged, {"forbidden": forbidden, "unchanged": unchanged})

    lab.kubectl(*command, "--as=system:serviceaccount:saf-test:audit-analyst")
    stored = get_record()
    lab.check("positive", "The scoped analyst can save a disposition and an independent read confirms the same alert identifier",
              stored == {**start, "disposition": "reviewed-benign-fixture"}, stored)
    return {"ordinary_forbidden": forbidden, "after_denial_unchanged": unchanged, "stored": stored}


def _private_kubectl(lab, *args):
    """Capture the selected case-local source log without logging raw rows."""
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
               f"kind-{lab.cluster}", "--namespace", "saf-test", *args]
    try:
        result = subprocess.run(command, text=True, capture_output=True,
                                env=lab.env, timeout=15)
    except OSError:
        lab.block("Private fixture registry evidence read failed (class=kubectl-unavailable; details suppressed)")
    except subprocess.TimeoutExpired:
        lab.block("Private fixture registry evidence read failed (class=exec-timeout; details suppressed)")
    if result.returncode:
        diagnostic = result.stderr.lower()
        if "permission denied" in diagnostic:
            category = "audit-file-permission"
        elif "no such file" in diagnostic or "not found" in diagnostic:
            category = "audit-file-missing"
        elif "unable to upgrade connection" in diagnostic or "error from server" in diagnostic:
            category = "exec-transport"
        else:
            category = "kubectl-nonzero"
        lab.block(f"Private fixture registry evidence read failed (class={category}; details suppressed)")
    return result.stdout


def _zot_config():
    return json.dumps({
        "distSpecVersion": "1.1.0",
        "storage": {"rootDirectory": "/var/lib/registry"},
        "log": {"level": "info", "audit": REGISTRY_AUDIT},
        "http": {
            "address": "0.0.0.0", "port": "5000",
            "auth": {"htpasswd": {"path": "/auth/htpasswd"}},
            "accessControl": {"repositories": {REGISTRY_REPO: {"defaultPolicy": ["read", "create"]}}},
        },
    }, separators=(",", ":"))


def _registry_deployment():
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": REGISTRY},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": REGISTRY}},
                 "template": {"metadata": {"labels": {"app": REGISTRY}},
                              "spec": {"automountServiceAccountToken": False,
                                       "containers": [
                                           {"name": "zot", "image": ZOT_IMAGE,
                                            "args": ["serve", "/etc/zot/config.json"],
                                            "ports": [{"name": "registry", "containerPort": 5000}],
                                            "readinessProbe": {"tcpSocket": {"port": 5000}, "periodSeconds": 1},
                                            "resources": {"requests": {"cpu": "20m", "memory": "64Mi"},
                                                          "limits": {"cpu": "200m", "memory": "192Mi"}},
                                            "volumeMounts": [
                                                {"name": "config", "mountPath": "/etc/zot", "readOnly": True},
                                                {"name": "auth", "mountPath": "/auth", "readOnly": True},
                                                {"name": "data", "mountPath": "/var/lib/registry"},
                                                {"name": "audit", "mountPath": "/audit"}]},
                                           {"name": "audit-reader", "image": BUSYBOX_IMAGE,
                                            "command": ["sh", "-c", "sleep 3600"],
                                            "securityContext": {"allowPrivilegeEscalation": False,
                                                                "capabilities": {"drop": ["ALL"]},
                                                                # Zot writes this native audit file as its
                                                                # default user. Match 0905-040's reader pattern:
                                                                # isolated root container, read-only log mount.
                                                                "runAsUser": 0,
                                                                "readOnlyRootFilesystem": True},
                                            "resources": {"requests": {"cpu": "5m", "memory": "8Mi"},
                                                          "limits": {"cpu": "50m", "memory": "16Mi"}},
                                            "volumeMounts": [{"name": "audit", "mountPath": "/audit", "readOnly": True}]}],
                                       "volumes": [
                                           {"name": "config", "configMap": {"name": "zot-source-config"}},
                                           {"name": "auth", "secret": {"secretName": "zot-source-auth",
                                               "items": [{"key": "htpasswd", "path": "htpasswd"}]}},
                                           {"name": "data", "emptyDir": {"sizeLimit": "32Mi"}},
                                           {"name": "audit", "emptyDir": {"sizeLimit": "4Mi"}}]}}},
    }


def _setup_zot(lab):
    # Reuse the existing pinned Zot version; password and htpasswd are case-only.
    auth_dir = lab.kubeconfig.parent / "zot-alert-auth"
    auth_dir.mkdir(mode=0o700)
    password = secrets.token_urlsafe(24)
    result = subprocess.run(("htpasswd", "-Bni", REGISTRY_ACTOR), input=password + "\n",
                            text=True, capture_output=True, timeout=15, env=lab.env)
    if result.returncode or not result.stdout.startswith(REGISTRY_ACTOR + ":"):
        lab.block("Could not prepare the disposable registry identity")
    htpasswd_path = auth_dir / "htpasswd"
    htpasswd_path.touch(mode=0o600, exist_ok=False)
    htpasswd_path.write_text(result.stdout)
    password_path = auth_dir / "password"
    password_path.touch(mode=0o600, exist_ok=False)
    password_path.write_text(password)
    try:
        lab.kubectl("create", "secret", "generic", "zot-source-auth",
                    f"--from-file=htpasswd={htpasswd_path}", f"--from-file=password={password_path}")
    finally:
        shutil.rmtree(auth_dir, ignore_errors=True)
    password = None
    result = None

    _create(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                  "metadata": {"name": "zot-source-config"},
                  "data": {"config.json": _zot_config()}})
    _create(lab, _registry_deployment())
    _create(lab, {"apiVersion": "v1", "kind": "Service", "metadata": {"name": REGISTRY},
                  "spec": {"selector": {"app": REGISTRY},
                           "ports": [{"name": "registry", "port": 5000, "targetPort": 5000}]}})

    client = _container("zot-client", command=["python", "-B", "-c", "import time; time.sleep(3600)"],
                        mounts=[{"name": "code", "mountPath": "/app", "readOnly": True},
                                {"name": "auth", "mountPath": "/auth", "readOnly": True}])
    client["image"] = PYTHON_IMAGE
    client["resources"] = {"requests": {"cpu": "10m", "memory": "32Mi"},
                           "limits": {"cpu": "100m", "memory": "96Mi"}}
    _create(lab, _deployment("zot-client", client, [
        {"name": "code", "configMap": {"name": "audit-review-code"}},
        {"name": "auth", "secret": {"secretName": "zot-source-auth",
             "items": [{"key": "password", "path": "password"}]}}]))
    lab.kubectl("rollout", "status", f"deployment/{REGISTRY}", "--timeout=90s", timeout=100)
    lab.kubectl("rollout", "status", "deployment/zot-client", "--timeout=90s", timeout=100)


def _native_zot_event(lab):
    probe = lab.kubectl("exec", "deployment/zot-client", "--", "python", "-B", "/app/zot_probe.py",
                        f"http://{REGISTRY}:5000", timeout=30)
    probe_result = json.loads(probe.stdout.strip().splitlines()[-1])
    if probe_result != {"create_status": 201, "pull_status": 200,
                        "manifest_digest_matches": True, "payload_kind": "empty-config-no-layers"}:
        lab.block("Bounded local Zot marker operation did not complete as expected")

    command = ("exec", "deployment/zot-source", "-c", "audit-reader", "--", "cat", REGISTRY_AUDIT)
    deadline = time.monotonic() + 20
    matching = []
    while time.monotonic() < deadline:
        raw = _private_kubectl(lab, *command)
        rows = []
        for line in raw.splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if (row.get("message") == "HTTP API Audit"
                    and row.get("action") == "PUT"
                    and row.get("object") == REGISTRY_PATH
                    and row.get("status") == 201):
                rows.append((line, row))
        matching = rows
        if matching:
            break
        time.sleep(0.4)
    if len(matching) != 1:
        lab.block("Expected one exact Zot audit event for the inert marker publish")
    line, source_row = matching[0]
    actor = source_row.get("subject") or source_row.get("username")
    if actor != REGISTRY_ACTOR:
        lab.block("The selected Zot audit record did not bind the expected case identity")
    event_identity = "\n".join((source_row["action"], source_row["object"],
                                 str(source_row["status"]), actor))
    event_id = "zot-" + hashlib.sha256(event_identity.encode()).hexdigest()[:20]
    normalized = {
        "event_id": event_id, "source": "zot-native-audit", "provider": "zot-v2.1.23",
        "provider_action": "PUT", "normalized_action": "publish",
        "repository": REGISTRY_REPO, "actor": actor,
        "classification": "sensitive-operation",
    }
    return normalized, {"probe": probe_result, "matched_native_audit_rows": len(matching),
                       "method": source_row["action"], "path_matches": True,
                       "status": source_row["status"], "actor_matches": True,
                       "source_event_id": event_id,
                       "raw_event_recorded": False, "credential_values_recorded": False}


def _receiver(lab):
    raw = _json_exec(lab, ["python", "-B", "/app/receiver_observe.py",
                           "https://audit-alert-receiver.saf-test.svc.cluster.local:8443"])
    return raw


def _expected_receiver_records(actual_event=None):
    records = [
        {"alert_id": "alert-audit-001", "event_id": "audit-001", "rule": "sensitive-publish",
         "actor": "fixture-publisher", "repository": "saf-test/model-a"},
        {"alert_id": "alert-audit-003", "event_id": "audit-003", "rule": "anomalous-pull",
         "actor": "fixture-reader", "repository": "saf-test/model-a"},
        {"alert_id": "alert-audit-004", "event_id": "audit-004", "rule": "sensitive-delete",
         "actor": "fixture-maintainer", "repository": "saf-test/model-a"},
        {"alert_id": "alert-audit-005", "event_id": "audit-005", "rule": "sensitive-permission-change",
         "actor": "fixture-maintainer", "repository": "saf-test/model-a"},
        {"alert_id": "alert-audit-006", "event_id": "audit-006", "rule": "sensitive-administration",
         "actor": "fixture-admin", "repository": "saf-test/model-a"},
    ]
    if actual_event:
        records.append({"alert_id": "alert-" + actual_event["event_id"],
                        "event_id": actual_event["event_id"], "rule": "sensitive-publish",
                        "actor": REGISTRY_ACTOR, "repository": REGISTRY_REPO})
    return sorted(records, key=lambda row: row["alert_id"])


def verify_zot_alert_route(lab):
    _setup_zot(lab)
    event, source = _native_zot_event(lab)
    before = _receiver(lab)
    pre_auth_state = before
    wrong_auth = _json_exec(lab, ["python", "-B", "/app/receiver_auth_probe.py",
                                 "https://audit-alert-receiver.saf-test.svc.cluster.local:8443"])
    after_wrong_auth = _receiver(lab)
    auth_denial_ok = (wrong_auth == {"status": 401, "wrong_credential_rejected": True}
                      and after_wrong_auth == before
                      and "auth-probe-denied" not in after_wrong_auth["alert_ids"])
    before = after_wrong_auth
    forwarded = _json_exec(lab, ["python", "-B", "/app/forward.py",
                                 "http://audit-monitor:8080", json.dumps(event, sort_keys=True)])
    after = _receiver(lab)
    replayed = _json_exec(lab, ["python", "-B", "/app/forward.py",
                                "http://audit-monitor:8080", json.dumps(event, sort_keys=True)])
    after_replay = _receiver(lab)
    expected_before = _expected_receiver_records()
    expected_after = _expected_receiver_records(event)
    before_ok = before == {"status": 200,
                           "alert_ids": sorted(row["alert_id"] for row in expected_before),
                           "events": sorted(row["event_id"] for row in expected_before),
                           "rules": sorted(row["rule"] for row in expected_before),
                           "records": expected_before, "duplicates": 0}
    expected_forward = {"status": 201, "event_count": 9, "duplicate_count": 8,
                        "alert_ids": sorted(row["alert_id"] for row in expected_after)}
    expected_replay = {"status": 201, "event_count": 9, "duplicate_count": 9,
                       "alert_ids": sorted(row["alert_id"] for row in expected_after)}
    route_ok = (before_ok and forwarded == expected_forward and replayed == expected_replay
                and after == {"status": 200,
                              "alert_ids": sorted(row["alert_id"] for row in expected_after),
                              "events": sorted(row["event_id"] for row in expected_after),
                              "rules": sorted(row["rule"] for row in expected_after),
                              "records": expected_after, "duplicates": 0}
                and after_replay == after)
    lab.check("positive", "One actual Zot audit publish maps to a routed case-local alert; quiet events stay absent and replay does not redeliver",
              route_ok, {"native_zot_source": source, "receiver_before_zot": before,
                         "receiver_after_zot": after, "forwarded": forwarded,
                         "forwarded_replay": replayed,
                         "ordinary_and_out_of_scope_events_delivered": False,
                         "external_alerts_sent": False})
    lab.check("green", "Verified TLS receiver rejects wrong credentials without mutation and accepts the authorized Zot-derived alert exactly once",
              auth_denial_ok and route_ok,
              {"wrong_credential_status": wrong_auth["status"],
               "unauthorized_state_unchanged": after_wrong_auth == pre_auth_state,
               "unauthorized_probe_absent": "auth-probe-denied" not in after_wrong_auth["alert_ids"],
               "authorized_delivery_status": forwarded["status"],
               "authorized_zot_alert_present": "alert-" + event["event_id"] in after["alert_ids"],
               "authorized_tls_verification": True,
               "authorized_replay_unchanged": after_replay == after,
               "external_alerts_sent": False})
    routed = next(row for row in expected_after if row["event_id"] == event["event_id"])
    return routed


def review_routed_zot_alert(lab, alert):
    """Exercise a real projected analyst identity on the exact received Zot event."""
    review_name = "zot-alert-review"
    record = {"alert_id": alert["alert_id"], "event_id": alert["event_id"],
              "disposition": "unreviewed"}
    _create(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                  "metadata": {"name": review_name}, "data": record})
    group = "rbac.authorization.k8s.io"
    for name, verbs in (("zot-alert-observer", ["get"]),
                        ("zot-alert-analyst", ["get", "patch"])):
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": name}})
        lab.create({"apiVersion": f"{group}/v1", "kind": "Role", "metadata": {"name": name},
                    "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                               "resourceNames": [review_name], "verbs": verbs}]})
        lab.create({"apiVersion": f"{group}/v1", "kind": "RoleBinding", "metadata": {"name": name},
                    "subjects": [{"kind": "ServiceAccount", "name": name, "namespace": "saf-test"}],
                    "roleRef": {"apiGroup": group, "kind": "Role", "name": name}})

    def run_identity(name, service_account, action):
        _create(lab, {
            "apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
            "spec": {"restartPolicy": "Never", "serviceAccountName": service_account,
                     "automountServiceAccountToken": True,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534},
                     "containers": [{"name": "review", "image": PYTHON_IMAGE,
                                     "imagePullPolicy": "IfNotPresent",
                                     "command": ["python", "-B", "/app/projected_review.py",
                                                 action, review_name, alert["alert_id"]],
                                     "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                                   "limits": {"cpu": "100m", "memory": "64Mi"}},
                                     "securityContext": {"allowPrivilegeEscalation": False,
                                                         "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}},
                                     "volumeMounts": [{"name": "code", "mountPath": "/app",
                                                       "readOnly": True}]}],
                     "volumes": [{"name": "code", "configMap": {"name": "audit-review-code"}}]},
        })
        lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{name}",
                    "--timeout=90s", timeout=100)
        result = json.loads(lab.kubectl("logs", f"pod/{name}").stdout)
        lab.kubectl("delete", "pod", name, "--wait=true")
        return result

    denied = run_identity("zot-review-denied", "zot-alert-observer", "deny")
    approved = run_identity("zot-review-approved", "zot-alert-analyst", "approve")
    readback = run_identity("zot-review-readback", "zot-alert-observer", "readback")
    lab.check("positive", "Projected observer is denied disposition writes while the projected scoped analyst acknowledges the exact Zot alert and an independent projected observer reads back its persisted record",
              denied == {"patch_forbidden": True, "read_ok": True, "unchanged": True,
                         "alert_id_matches": True}
              and approved == {"patch_accepted": True}
              and readback == {"read_ok": True, "exact_alert_id": True,
                               "exact_event_id": True, "reviewed": True},
              {"denied_observer": denied, "analyst_write": approved,
               "independent_readback": readback, "alert_id": alert["alert_id"],
               "token_or_credential_emitted": False})
    return {"alert_id": alert["alert_id"], "denied_observer": denied,
            "analyst_write": approved, "independent_readback": readback}


def run(lab):
    _setup(lab)
    observations = _json_exec(lab, ["python", "-B", "/app/fixture.py", f"http://audit-monitor:{PORT}"])
    check_events(lab, observations)
    disposition = review_alert(lab, observations["enforced"]["alerts"]["alert-audit-003"])
    zot_alert = verify_zot_alert_route(lab)
    zot_disposition = review_routed_zot_alert(lab, zot_alert)
    (lab.evidence / "normalized-audit-alert-review.json").write_text(
        json.dumps({"events": observations, "analyst_review": disposition,
                    "zot_alert_review": zot_disposition}, indent=2, sort_keys=True) + "\n")
