"""Probe Zot's documented repository access-control immutability policy."""
import json
import secrets
import subprocess
from pathlib import Path


HERE = Path(__file__).resolve().parent
SCOPE = (
    "A single kind cluster runs isolated Zot v2.1.23 registries for one exact repo and "
    "authenticated case-owned OCI Distribution API actors. An open policy allows read/create/update/delete; "
    "a guarded policy allows read/create only; a third registry adds a deliberately explicit adminPolicy "
    "override for one synthetic actor. Fixed inert OCI manifests exercise initial tag creation, same-tag "
    "overwrite, digest readback, manifest deletion/recreation, and the documented adminPolicy boundary. "
    "The case checks native audit and filtered HTTP access events for selected operations. It does not "
    "establish deployed identity governance, durable audit forwarding, sync/retention behavior, or protection "
    "against storage administrators and registry-internal processes."
)

ZOT_IMAGE = "ghcr.io/project-zot/zot:v2.1.23@sha256:9d3de83ac2099e6f4843045b4c9b65b7e8baf40f92d28f54906dee9d4d390fd7"
CLIENT_IMAGE = "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
REPO = "saf-test/model"
PORT = 5000
AUDIT_FILE = "/audit/events.jsonl"
BUSYBOX = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"


def _config(actions, *, admin_override=False):
    access_control = {
        "repositories": {REPO: {"defaultPolicy": actions}}
    }
    if admin_override:
        access_control["adminPolicy"] = {
            "users": ["fixture-override"],
            "actions": ["read", "create", "update", "delete"],
        }
    return json.dumps({
        "distSpecVersion": "1.1.0",
        "storage": {"rootDirectory": "/var/lib/registry"},
        "log": {"level": "info", "audit": AUDIT_FILE},
        "http": {
            "address": "0.0.0.0",
            "port": str(PORT),
            "auth": {"htpasswd": {"path": "/auth/htpasswd"}},
            "accessControl": access_control,
        },
    }, separators=(",", ":"))


def _resource(lab, obj):
    lab.kubectl("create", "-f", "-", payload=json.dumps(obj))


def _registry(name, actions, *, admin_override=False):
    config_name = f"{name}-config"
    return [
        {
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": config_name},
            "data": {"config.json": _config(actions, admin_override=admin_override)},
        },
        {
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": name},
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": name}},
                "template": {
                    "metadata": {"labels": {"app": name}},
                    "spec": {
                        "automountServiceAccountToken": False,
                        "containers": [{
                            "name": "zot", "image": ZOT_IMAGE,
                            "readinessProbe": {"tcpSocket": {"port": PORT}, "periodSeconds": 1},
                            "args": ["serve", "/etc/zot/config.json"],
                            "ports": [{"name": "registry", "containerPort": PORT}],
                            "resources": {
                                "requests": {"cpu": "25m", "memory": "64Mi"},
                                "limits": {"cpu": "250m", "memory": "192Mi"},
                            },
                            "volumeMounts": [
                                {"name": "config", "mountPath": "/etc/zot", "readOnly": True},
                                {"name": "auth", "mountPath": "/auth", "readOnly": True},
                                {"name": "data", "mountPath": "/var/lib/registry"},
                                {"name": "audit", "mountPath": "/audit"},
                            ],
                        }, {"name": "audit-reader", "image": BUSYBOX,
                             "command": ["sleep", "3600"],
                             "volumeMounts": [{"name": "audit", "mountPath": "/audit", "readOnly": True}],
                             "resources": {"requests": {"cpu": "5m", "memory": "8Mi"}}}],
                        "volumes": [
                            {"name": "config", "configMap": {"name": config_name}},
                            {"name": "auth", "secret": {"secretName": "saf-zot-fixture-auth", "items": [{"key": "htpasswd", "path": "htpasswd"}]}},
                            {"name": "data", "emptyDir": {}},
                            {"name": "audit", "emptyDir": {}},
                        ],
                    },
                },
            },
        },
        {
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": name},
            "spec": {
                "selector": {"app": name},
                "ports": [{"name": "registry", "port": PORT, "targetPort": PORT}],
            },
        },
    ]


def _wait_ready(lab, name):
    lab.kubectl("rollout", "status", f"deployment/{name}", "--timeout=100s", timeout=110)


def _probe(lab, registry, mode):
    result = lab.kubectl(
        "exec", "deployment/oci-probe", "--", "python", "/probe/probe.py",
        f"http://{registry}:{PORT}", mode,
        timeout=45, allow_failure=True,
    )
    try:
        observation = json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        lab.block("OCI probe returned no filtered JSON observation")
    if not isinstance(observation, dict) or observation.get("ok") is not True:
        lab.block(f"OCI API probe did not complete its expected sequence: {observation.get('error', 'unknown')}")
    return observation


def _filtered_logs(lab, *args):
    command = ("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
               "--namespace", "saf-test", *args)
    result = subprocess.run(command, text=True, capture_output=True, timeout=25, env=lab.env)
    if result.returncode:
        lab.block("Could not read the disposable registry event stream")
    for line in result.stdout.splitlines():
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def _registry_evidence(lab, protected_digest):
    tag_path = f"/v2/{REPO}/manifests/reviewed-v1"
    delete_path = f"/v2/{REPO}/manifests/{protected_digest}"
    targets = {("PUT", tag_path), ("DELETE", delete_path)}

    def selected(rows, message, fields):
        method, object_path, status = fields
        return [{"method": event[method], "path": event[object_path], "status": event.get(status),
                 "time": event.get("time"), "actor": event.get("subject") or event.get("username")}
                for event in rows if event.get("message") == message
                and (event.get(method), event.get(object_path)) in targets]

    audit = selected(_filtered_logs(lab, "exec", "deployment/zot-locked", "-c", "audit-reader",
                                    "--", "cat", AUDIT_FILE),
                     "HTTP API Audit", ("action", "object", "status"))
    access = selected(_filtered_logs(lab, "logs", "deployment/zot-locked", "-c", "zot"),
                      "HTTP API", ("method", "path", "statusCode"))
    created = any(row["method"] == "PUT" and row["status"] == 201 for row in audit)
    native_denials = [row for row in audit if row["status"] == 403]
    access_denials = {(row["method"], row["path"]) for row in access if row["status"] == 403}
    evidence = {"native_audit": audit, "http_access": access}
    (lab.evidence / "zot-audit-observations.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    lab.check("green", "Native audit records the allowed tag creation and the access stream records both denied mutations",
              created and not native_denials and access_denials == targets,
              {"native_audit_success": created, "native_audit_denial_count": len(native_denials),
               "http_denied_methods": sorted(method for method, _ in access_denials)})
    return evidence


def _fixture_identity(lab):
    auth = lab.kubeconfig.parent / "registry-auth"
    auth.mkdir(mode=0o700)
    entries = []
    for username in ("fixture-publisher", "fixture-override"):
        password = secrets.token_urlsafe(24)
        result = subprocess.run(("htpasswd", "-Bni", username), input=password+"\n",
                                text=True, capture_output=True, timeout=15, env=lab.env)
        if result.returncode or not result.stdout.startswith(username + ":"):
            lab.block("Could not prepare the disposable registry identity")
        entries.append(result.stdout)
        name = username + "-password"
        path = auth / name
        path.touch(mode=0o600, exist_ok=False)
        path.write_text(password)
    htpasswd = auth / "htpasswd"
    htpasswd.touch(mode=0o600, exist_ok=False)
    htpasswd.write_text("".join(entries))
    lab.kubectl("create", "secret", "generic", "saf-zot-fixture-auth",
                f"--from-file=htpasswd={htpasswd}",
                f"--from-file=fixture-publisher-password={auth/'fixture-publisher-password'}",
                f"--from-file=fixture-override-password={auth/'fixture-override-password'}")


def run(lab):
    _fixture_identity(lab)
    for resource in _registry("zot-open", ["read", "create", "update", "delete"]):
        _resource(lab, resource)
    for resource in _registry("zot-locked", ["read", "create"]):
        _resource(lab, resource)
    for resource in _registry("zot-admin-override", ["read", "create"], admin_override=True):
        _resource(lab, resource)

    client = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "oci-probe"},
        "data": {"probe.py": (HERE / "probe.py").read_text()},
    }
    _resource(lab, client)
    _resource(lab, {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": "oci-probe"},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "oci-probe"}},
            "template": {
                "metadata": {"labels": {"app": "oci-probe"}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "containers": [{
                        "name": "probe", "image": CLIENT_IMAGE,
                        "command": ["python", "-c", "import time; time.sleep(3600)"],
                        "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                      "limits": {"cpu": "100m", "memory": "96Mi"}},
                        "volumeMounts": [{"name": "probe", "mountPath": "/probe", "readOnly": True},
                                         {"name": "auth", "mountPath": "/auth", "readOnly": True}],
                    }],
                    "volumes": [{"name": "probe", "configMap": {"name": "oci-probe"}},
                                {"name": "auth", "secret": {"secretName": "saf-zot-fixture-auth", "items": [
                                    {"key": "fixture-publisher-password", "path": "fixture-publisher-password"},
                                    {"key": "fixture-override-password", "path": "fixture-override-password"},
                                ]}}],
                },
            },
        },
    })

    _wait_ready(lab, "zot-open")
    _wait_ready(lab, "zot-locked")
    _wait_ready(lab, "zot-admin-override")
    _wait_ready(lab, "oci-probe")

    open_result = _probe(lab, "zot-open", "open")
    lab.check("red", "Open policy permits initial creation and digest read",
              open_result.get("initial_status") == 201,
              {key: open_result.get(key) for key in ("initial_status", "artifact_a_digest")})
    lab.check("red", "Unrestricted Zot accepts same-tag overwrite and manifest delete/recreation",
              open_result.get("overwrite_status") == 201
              and open_result.get("overwrite_digest") == open_result.get("artifact_b_digest")
              and open_result.get("delete_status") in (200, 202)
              and open_result.get("recreate_status") == 201
              and open_result.get("recreated_digest") == open_result.get("artifact_a_digest"),
              {key: open_result.get(key) for key in (
                  "initial_status", "overwrite_status", "overwrite_digest", "artifact_b_digest",
                  "delete_status", "recreate_status", "recreated_digest", "artifact_a_digest")})

    locked_result = _probe(lab, "zot-locked", "locked")
    lab.check("green", "Read/create-only policy permits initial tag creation and digest read",
              locked_result.get("initial_status") == 201,
              {key: locked_result.get(key) for key in ("initial_status", "artifact_a_digest")})
    lab.check("green", "Read/create-only policy blocks overwrite; post-read digest is unchanged",
              locked_result.get("overwrite_status") == 403
              and locked_result.get("after_overwrite_digest") == locked_result.get("artifact_a_digest"),
              {key: locked_result.get(key) for key in (
                  "initial_status", "overwrite_status", "after_overwrite_digest", "artifact_a_digest")})
    lab.check("green", "Read/create-only policy blocks digest deletion and preserves the tag",
              locked_result.get("delete_status") == 403
              and locked_result.get("after_delete_digest") == locked_result.get("artifact_a_digest"),
              {key: locked_result.get(key) for key in (
                  "delete_status", "after_delete_digest", "artifact_a_digest")})
    lab.check("positive", "Read/create-only policy still allows a distinct first tag and digest pull",
              locked_result.get("positive_create_status") == 201
              and locked_result.get("positive_digest") == locked_result.get("artifact_b_digest"),
              {key: locked_result.get(key) for key in (
                  "positive_create_status", "positive_digest", "artifact_b_digest")})

    (lab.evidence / "zot-immutability.json").write_text(
        json.dumps({"open": open_result, "locked": locked_result}, indent=2, sort_keys=True) + "\n")

    _registry_evidence(lab, locked_result["artifact_a_digest"])
    admin_result = _probe(lab, "zot-locked", "admin-denied")
    override_result = _probe(lab, "zot-admin-override", "admin-override")
    tag_path = f"/v2/{REPO}/manifests/reviewed-v1"
    admin_access_identity = any(
        (event.get("subject") or event.get("username")) == "fixture-override"
        and event.get("method") == "PUT" and event.get("path") == tag_path
        and event.get("statusCode") == 201
        for event in _filtered_logs(lab, "logs", "deployment/zot-admin-override", "-c", "zot")
        if event.get("message") == "HTTP API")
    admin_audit_identity = any(
        event.get("message") == "HTTP API Audit"
        and (event.get("subject") or event.get("username")) == "fixture-override"
        and event.get("action") == "PUT" and event.get("object") == tag_path
        and event.get("status") == 201
        for event in _filtered_logs(
            lab, "exec", "deployment/zot-admin-override", "-c", "audit-reader",
            "--", "cat", AUDIT_FILE))
    admin_boundary = (
        admin_result.get("overwrite_status") == 403
        and admin_result.get("after_digest") == locked_result["artifact_a_digest"]
        and override_result.get("initial_status") == 201
        and override_result.get("overwrite_status") == 201
        and override_result.get("before_status") == 200
        and override_result.get("after_digest") == override_result.get("artifact_b_digest")
        and admin_access_identity and admin_audit_identity)
    lab.check(
        "green",
        "The protected repository denies the override identity unless Zot adminPolicy explicitly grants mutation; an explicit override is visible in actor logs",
        admin_boundary,
        {"override_identity_denied_without_admin_policy":
         admin_result.get("overwrite_status") == 403
         and admin_result.get("after_digest") == locked_result["artifact_a_digest"],
         "explicit_admin_policy_allows_override":
         override_result.get("overwrite_status") == 201
         and override_result.get("after_digest") == override_result.get("artifact_b_digest"),
         "access_event_names_override_actor": admin_access_identity,
         "native_audit_names_override_actor": admin_audit_identity})
    (lab.evidence / "zot-admin-boundary.json").write_text(json.dumps({
        "strict_policy_denies_override_identity": admin_result.get("overwrite_status") == 403,
        "explicit_admin_policy_allows_override": override_result.get("overwrite_status") == 201,
        "access_event_names_override_actor": admin_access_identity,
        "native_audit_names_override_actor": admin_audit_identity,
    }, indent=2, sort_keys=True) + "\n")
