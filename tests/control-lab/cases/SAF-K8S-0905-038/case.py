"""Exercise Zot repository/action authorization through OCI Distribution requests."""
import json
import secrets
import subprocess
from pathlib import Path


HERE = Path(__file__).resolve().parent
SCOPE = (
    "A disposable Kind cluster runs two Zot v2.1.23 registries with identical fixture accounts: "
    "a permissive baseline and a scoped policy. A running Kubernetes inference client receives "
    "only a case-owned read credential; a publisher can read/create in training/model; and a "
    "separate steward can read/create/update/delete there. The registry enforces authentication "
    "and repository/action decisions at OCI Distribution endpoints. The Kubernetes service "
    "account labels/binds the inference workload only; it is not federated to Zot. This does not "
    "test OIDC/IAM federation, Harbor/MLflow/Hugging Face Hub, real model payloads, production "
    "TLS/secret management, human-role governance, or deployed registry operations."
)

ZOT_IMAGE = "ghcr.io/project-zot/zot:v2.1.23@sha256:9d3de83ac2099e6f4843045b4c9b65b7e8baf40f92d28f54906dee9d4d390fd7"
CLIENT_IMAGE = "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
PORT = 5000
ACCOUNTS = ("inference", "publisher", "steward", "seed")


def _config(scoped):
    repos = {"**": {"defaultPolicy": [] if scoped else ["read", "create", "update", "delete"]}}
    if scoped:
        repos["serving/model"] = {
            "policies": [{"users": ["inference"], "actions": ["read"]}],
            "defaultPolicy": [],
        }
        repos["training/model"] = {
            "policies": [
                {"users": ["publisher"], "actions": ["read", "create"]},
                {"users": ["steward"], "actions": ["read", "create", "update", "delete"]},
                {"users": ["seed"], "actions": ["read", "create", "update", "delete"]},
            ],
            "defaultPolicy": [],
        }
        repos["serving/model"]["policies"].append(
            {"users": ["seed"], "actions": ["read", "create", "update", "delete"]}
        )
    return {
        "distSpecVersion": "1.1.0",
        "storage": {"rootDirectory": "/var/lib/registry"},
        "http": {
            "address": "0.0.0.0", "port": str(PORT),
            "auth": {"htpasswd": {"path": "/auth/htpasswd"}},
            "accessControl": {"repositories": repos},
        },
    }


def _resource(lab, obj):
    lab.kubectl("create", "-f", "-", payload=json.dumps(obj))


def _deployment(name, username, service_account):
    mounts = [{"name": "probe", "mountPath": "/probe", "readOnly": True}]
    volumes = [{"name": "probe", "configMap": {"name": "registry-probe"}}]
    mounts.append({"name": "auth", "mountPath": "/auth", "readOnly": True})
    volumes.append({"name": "auth", "secret": {
        "secretName": f"registry-{username}",
        "items": [{"key": "password", "path": "password"}],
    }})
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {
                    "automountServiceAccountToken": False,
                    **({"serviceAccountName": service_account} if service_account else {}),
                    "containers": [{
                        "name": "client", "image": CLIENT_IMAGE,
                        "command": ["python", "-c", "import time; time.sleep(3600)"],
                        "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                      "limits": {"cpu": "100m", "memory": "96Mi"}},
                        "volumeMounts": mounts,
                    }],
                    "volumes": volumes,
                },
            },
        },
    }


def _registry(name, scoped, auth_secret):
    config_name = f"{name}-config"
    return [
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": config_name},
         "data": {"config.json": json.dumps(_config(scoped), separators=(",", ":"))}},
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name},
         "spec": {"replicas": 1, "selector": {"matchLabels": {"app": name}},
                  "template": {"metadata": {"labels": {"app": name}}, "spec": {
                      "automountServiceAccountToken": False,
                      "containers": [{"name": "zot", "image": ZOT_IMAGE,
                                      "args": ["serve", "/etc/zot/config.json"],
                                      "ports": [{"name": "registry", "containerPort": PORT}],
                                      "readinessProbe": {"tcpSocket": {"port": PORT}, "periodSeconds": 1},
                                      "resources": {"requests": {"cpu": "25m", "memory": "64Mi"},
                                                    "limits": {"cpu": "250m", "memory": "192Mi"}},
                                      "volumeMounts": [
                                          {"name": "config", "mountPath": "/etc/zot", "readOnly": True},
                                          {"name": "auth", "mountPath": "/auth", "readOnly": True},
                                          {"name": "data", "mountPath": "/var/lib/registry"},
                                      ]}],
                      "volumes": [{"name": "config", "configMap": {"name": config_name}},
                                  {"name": "auth", "secret": {"secretName": auth_secret,
                                   "items": [{"key": "htpasswd", "path": "htpasswd"}]}},
                                  {"name": "data", "emptyDir": {}}],
                  }}}},
        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
         "spec": {"selector": {"app": name},
                  "ports": [{"name": "registry", "port": PORT, "targetPort": PORT}]}},
    ]


def _secret(lab):
    """Create ephemeral bcrypt credentials without putting values in command logs."""
    auth_dir = lab.kubeconfig.parent / "zot-auth"
    auth_dir.mkdir(mode=0o700)
    passwords = {user: secrets.token_urlsafe(24) for user in ACCOUNTS}
    htpasswd_lines = []
    for username, password in passwords.items():
        result = subprocess.run(("htpasswd", "-Bni", username), input=password + "\n",
                                text=True, capture_output=True, timeout=15, env=lab.env)
        if result.returncode or not result.stdout.startswith(username + ":"):
            lab.block("Could not prepare the disposable registry identities")
        htpasswd_lines.append(result.stdout.rstrip("\n"))
        path = auth_dir / f"{username}.password"
        path.touch(mode=0o600, exist_ok=False)
        path.write_text(password)
        lab.kubectl("create", "secret", "generic", f"registry-{username}",
                    f"--from-file=password={path}")
    path = auth_dir / "htpasswd"
    path.touch(mode=0o600, exist_ok=False)
    path.write_text("\n".join(htpasswd_lines) + "\n")
    lab.kubectl("create", "secret", "generic", "zot-fixture-auth", f"--from-file=htpasswd={path}")


def _ready(lab, name):
    lab.kubectl("rollout", "status", f"deployment/{name}", "--timeout=100s", timeout=110)


def _probe(lab, client, registry, scenario, username):
    result = lab.kubectl("exec", f"deployment/{client}", "--", "python", "/probe/probe.py",
                         f"http://{registry}:{PORT}", scenario, username,
                         timeout=45, allow_failure=True)
    try:
        observation = json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        lab.block("OCI client returned no filtered JSON observation")
    if result.returncode or not isinstance(observation, dict) or observation.get("ok") is not True:
        lab.block("OCI request sequence failed outside its expected authorization responses")
    return observation


def run(lab):
    _secret(lab)
    _resource(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {"name": "registry-probe"},
                    "data": {"probe.py": (HERE / "probe.py").read_text()}})
    for name, scoped in (("zot-baseline", False), ("zot-scoped", True)):
        for obj in _registry(name, scoped, "zot-fixture-auth"):
            _resource(lab, obj)

    _resource(lab, {"apiVersion": "v1", "kind": "ServiceAccount",
                    "metadata": {"name": "inference-client"}})
    clients = (
        ("seed-client", "seed", None),
        ("inference-client", "inference", "inference-client"),
        ("publisher-client", "publisher", None),
        ("steward-client", "steward", None),
    )
    for name, username, service_account in clients:
        _resource(lab, _deployment(name, username, service_account))
    for name in ("zot-baseline", "zot-scoped", *(row[0] for row in clients)):
        _ready(lab, name)

    # Seed the same inert OCI artifacts in both registries through a short-lived
    # fixture identity. The seed account is not mounted into serving workloads.
    for registry in ("zot-baseline", "zot-scoped"):
        for repository in ("serving/model", "training/model"):
            _probe(lab, "seed-client", registry, f"seed:{repository}", "seed")

    baseline_pull = _probe(lab, "inference-client", "zot-baseline", "inference-scope", "inference")
    lab.check("red", "Before scoping, inference can read the other repository and write in its serving repository",
              baseline_pull["training_status"] == 200 and baseline_pull["serving_write_status"] == 201,
              {"method": "GET", "path": "/v2/training/model/manifests/stable",
               "cross_repository_read": baseline_pull["training_status"],
               "serving_write": baseline_pull["serving_write_status"]})
    baseline_write = _probe(lab, "publisher-client", "zot-baseline", "publisher-cycle", "publisher")
    lab.check("red", "Before scoping, publisher can overwrite and delete a manifest",
              baseline_write["update_status"] == 201 and baseline_write["delete_status"] == 202
              and baseline_write["cross_repo_create_status"] == 201,
              {"update_path": "/v2/training/model/manifests/stable",
               "update_status": baseline_write["update_status"],
               "delete_path": "/v2/training/model/manifests/sha256:<fixture>",
               "delete_status": baseline_write["delete_status"]})

    inference = _probe(lab, "inference-client", "zot-scoped", "inference-scope", "inference")
    lab.check("green", "Inference pulls only from the approved repository and cannot publish there",
              inference["serving_status"] == 200 and inference["training_status"] == 403
              and inference["serving_write_status"] == 403,
              {"serving_get_status": inference["serving_status"],
               "training_get_path": "/v2/training/model/manifests/stable",
               "training_get_status": inference["training_status"],
               "serving_write_status": inference["serving_write_status"]})
    publisher = _probe(lab, "publisher-client", "zot-scoped", "publisher-cycle", "publisher")
    lab.check("green", "Publisher creates a new tag but receives 403 for update and delete",
              publisher["create_status"] == 201 and publisher["update_status"] == 403
              and publisher["delete_status"] == 403 and publisher["cross_repo_create_status"] == 403
              and publisher["stable_digest_preserved"] is True,
              {"create_path": "/v2/training/model/manifests/published-v1",
               "create_status": publisher["create_status"],
               "update_path": "/v2/training/model/manifests/stable",
               "update_status": publisher["update_status"],
               "delete_path": publisher["delete_path"],
               "delete_status": publisher["delete_status"],
               "cross_repo_create_path": "/v2/serving/model/manifests/cross-repo",
               "cross_repo_create_status": publisher["cross_repo_create_status"],
               "stable_digest_preserved": publisher["stable_digest_preserved"]})
    steward = _probe(lab, "steward-client", "zot-scoped", "steward-cycle", "steward")
    lab.check("green", "Separate per-repository steward can modify and delete",
              steward["update_status"] == 201 and steward["delete_status"] == 202
              and steward["updated_digest_matches"] is True and steward["post_delete_status"] == 404,
              {"update_path": "/v2/training/model/manifests/stable",
               "update_status": steward["update_status"],
               "delete_path": steward["delete_path"],
               "delete_status": steward["delete_status"], "updated_digest_matches": steward["updated_digest_matches"],
               "post_delete_status": steward["post_delete_status"]})
    lab.check("positive", "Inference client receives only its scoped credential and still pulls the approved model",
              inference["serving_status"] == 200 and inference["serving_digest_matches"] is True,
              {"method": "GET", "path": "/v2/serving/model/manifests/stable",
               "status": inference["serving_status"],
               "content_digest_matches": inference["serving_digest_matches"]})

    (lab.evidence / "zot-rbac-observations.json").write_text(
        json.dumps({"baseline": {"pull": baseline_pull, "publisher": baseline_write},
                    "scoped": {"inference": inference, "publisher": publisher,
                               "steward": steward}}, indent=2, sort_keys=True) + "\n")
