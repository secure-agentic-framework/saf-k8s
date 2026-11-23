"""SAF-K8S-0905-039: review and remediate one Zot repository read entitlement."""
import json
import secrets
import subprocess
from copy import deepcopy
from pathlib import Path


HERE = Path(__file__).resolve().parent
ZOT_IMAGE = (
    "ghcr.io/project-zot/zot:v2.1.23@sha256:"
    "9d3de83ac2099e6f4843045b4c9b65b7e8baf40f92d28f54906dee9d4d390fd7"
)
CLIENT_IMAGE = (
    "docker.io/library/python:3.13.2-alpine@sha256:"
    "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
)
PORT = 5000
IDENTITIES = ("seed", "reviewed", "observer")
REPO = "team/model"
SCOPE = (
    "One disposable Kind cluster runs pinned Zot 2.1.23, a PVC-backed registry with a fixed inert OCI artifact. "
    "An approved fixture inventory identifies a standing read grant to remove. The same credential reads before "
    "review and receives an authorization denial after a registry restart. An independent reader still obtains "
    "the same digest. Organizational periodic review, identity lifecycle, every repository and other registry products "
    "require deployed evidence. The approved inventory and entitlement age are synthetic."
)


def _resource(lab, value):
    lab.kubectl("create", "-f", "-", payload=json.dumps(value))


def _config():
    policies = [{"users": ["seed"], "actions": ["read", "create", "update", "delete"]}]
    policies.append({"users": ["reviewed"], "actions": ["read"]})
    policies.append({"users": ["observer"], "actions": ["read"]})
    return {
        "distSpecVersion": "1.1.0",
        "storage": {"rootDirectory": "/var/lib/registry"},
        "http": {
            "address": "0.0.0.0",
            "port": str(PORT),
            "auth": {"htpasswd": {"path": "/auth/htpasswd"}},
            "accessControl": {
                "repositories": {
                    "**": {"defaultPolicy": []},
                    REPO: {"policies": policies, "defaultPolicy": []},
                }
            },
        },
    }


def _policies(config, repository):
    return config["http"]["accessControl"]["repositories"][repository]["policies"]


def remove_fixture_grant(config, repository, identity):
    revised = deepcopy(config)
    policies = _policies(revised, repository)
    policies[:] = [policy for policy in policies if policy["users"] != [identity]]
    return revised


def _secret(lab):
    auth_dir = lab.kubeconfig.parent / "saf-k8s-0905-039-auth"
    auth_dir.mkdir(mode=0o700)
    passwords = {name: secrets.token_urlsafe(24) for name in IDENTITIES}
    lines = []
    for name, password in passwords.items():
        result = subprocess.run(
            ("htpasswd", "-Bni", name), input=password + "\n", text=True,
            capture_output=True, timeout=15, env=lab.env,
        )
        if result.returncode or not result.stdout.startswith(name + ":"):
            lab.block("Could not prepare disposable Zot fixture identities")
        lines.append(result.stdout.rstrip("\n"))
        path = auth_dir / f"{name}.password"
        path.touch(mode=0o600, exist_ok=False)
        path.write_text(password)
        lab.kubectl("create", "secret", "generic", f"registry-{name}",
                    f"--from-file=password={path}")

    path = auth_dir / "htpasswd"
    path.touch(mode=0o600, exist_ok=False)
    path.write_text("\n".join(lines) + "\n")
    lab.kubectl("create", "secret", "generic", "zot-fixture-auth",
                f"--from-file=htpasswd={path}")


def _registry_resources():
    config = _config()
    return [
        {"apiVersion": "v1", "kind": "ConfigMap",
         "metadata": {"name": "review-zot-config"},
         "data": {"config.json": json.dumps(config, separators=(",", ":"))}},
        {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
         "metadata": {"name": "review-zot-data"},
         "spec": {"accessModes": ["ReadWriteOnce"],
                  "resources": {"requests": {"storage": "1Gi"}}}},
        {"apiVersion": "apps/v1", "kind": "Deployment",
         "metadata": {"name": "review-zot"},
         "spec": {"replicas": 1, "strategy": {"type": "Recreate"},
                  "selector": {"matchLabels": {"app": "review-zot"}},
                  "template": {"metadata": {"labels": {"app": "review-zot"}},
                               "spec": {"automountServiceAccountToken": False,
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
                                        "volumes": [
                                            {"name": "config", "configMap": {"name": "review-zot-config"}},
                                            {"name": "auth", "secret": {"secretName": "zot-fixture-auth",
                                                "items": [{"key": "htpasswd", "path": "htpasswd"}]}},
                                            {"name": "data", "persistentVolumeClaim": {"claimName": "review-zot-data"}},
                                        ]}}}},
        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "review-zot"},
         "spec": {"selector": {"app": "review-zot"},
                  "ports": [{"name": "registry", "port": PORT, "targetPort": PORT}]}},
        {"apiVersion": "v1", "kind": "ConfigMap",
         "metadata": {"name": "review-probe"},
         "data": {"probe.py": (HERE / "probe.py").read_text()}},
        *(_client_deployment(identity) for identity in IDENTITIES),
    ]


def _client_deployment(identity):
    return {"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": f"{identity}-client"},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": f"{identity}-client"}},
                     "template": {"metadata": {"labels": {"app": f"{identity}-client"}},
                                  "spec": {"automountServiceAccountToken": False,
                                           "containers": [{"name": "client", "image": CLIENT_IMAGE,
                                                           "command": ["python", "-c", "import time; time.sleep(3600)"],
                                                           "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                                                         "limits": {"cpu": "100m", "memory": "96Mi"}},
                                                           "volumeMounts": [
                                                               {"name": "probe", "mountPath": "/probe", "readOnly": True},
                                                               {"name": "auth", "mountPath": f"/auth/{identity}", "readOnly": True},
                                                           ]}],
                                           "volumes": [
                                               {"name": "probe", "configMap": {"name": "review-probe"}},
                                               {"name": "auth", "secret": {
                                                   "secretName": f"registry-{identity}",
                                                   "items": [{"key": "password", "path": "password"}],
                                               }},
                                           ]}}}}


def _ready(lab, deployment):
    lab.kubectl("rollout", "status", f"deployment/{deployment}", "--timeout=100s", timeout=110)


def _probe(lab, identity, expected_digest):
    result = lab.kubectl(
        "exec", f"deployment/{identity}-client", "--", "python", "/probe/probe.py",
        f"http://review-zot:{PORT}", identity, expected_digest,
        timeout=30, allow_failure=True,
    )
    try:
        observation = json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        lab.block("Registry probe returned no filtered JSON observation")
    if result.returncode and observation.get("error") == "registry unavailable":
        lab.block("Registry service was unavailable")
    if observation.get("ok") is not True:
        lab.block("Registry probe failed outside the expected authorization response")
    return observation


def _read_config(lab):
    result = lab.kubectl("get", "configmap", "review-zot-config", "-o", "json")
    try:
        return json.loads(result.stdout)["data"]["config.json"]
    except (json.JSONDecodeError, KeyError, TypeError):
        lab.block("Could not read back the remediated Zot policy")


def _registry_uid(lab):
    pods = json.loads(lab.kubectl("get", "pods", "-l", "app=review-zot", "-o", "json").stdout)
    ready = [item["metadata"]["uid"] for item in pods["items"]
             if not item["metadata"].get("deletionTimestamp")
             and any(c["type"] == "Ready" and c["status"] == "True"
                     for c in item.get("status", {}).get("conditions", []))]
    if len(ready) != 1:
        lab.block("Expected one active Ready registry Pod")
    return ready[0]


def run(lab):
    _secret(lab)
    for obj in _registry_resources():
        _resource(lab, obj)
    _ready(lab, "review-zot")
    for identity in IDENTITIES:
        _ready(lab, f"{identity}-client")

    seed_result = lab.kubectl("exec", "deployment/seed-client", "--", "python", "/probe/probe.py",
                              f"http://review-zot:{PORT}", "seed", "seed", allow_failure=True, timeout=30)
    try:
        seed_observation = json.loads(seed_result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        lab.block("Fixture seed returned no filtered JSON observation")
    if seed_result.returncode or seed_observation.get("status") != 201:
        lab.block("Fixture seed did not create the expected repository artifact")
    stable_digest = seed_observation.get("digest")
    if not isinstance(stable_digest, str) or not stable_digest.startswith("sha256:"):
        lab.block("Fixture seed did not return a stable manifest digest")

    before_uid = _registry_uid(lab)
    persistent_claim = json.loads(lab.kubectl("get", "pvc/review-zot-data", "-o", "json").stdout)
    claim_uid = persistent_claim["metadata"]["uid"]
    before = _probe(lab, "reviewed", stable_digest)
    lab.check("red", "Standing identity reads the fixture repository before review",
              before.get("status") == 200 and before.get("digest_matches_expected") is True,
              {"method": before.get("method"), "path": before.get("path"),
               "identity": before.get("identity"), "status": before.get("status"),
               "digest_matches_seed": before.get("digest_matches_expected"),
               "synthetic_operation_approved": True,
               "approval_type": "manually_simulated_fixture_input"})

    actual_policy = json.loads(_read_config(lab))
    active = [rule["actions"] for rule in _policies(actual_policy, REPO) if rule["users"] == ["reviewed"]]
    if active != [["read"]]:
        lab.block("The running registry configuration did not contain the expected standing entitlement")
    entitlement = {"identity": "reviewed", "repository": REPO, "actions": active[0],
                   "declared_age_days": 120, "review_interval_days": 30}
    synthetic_operation_approval = {"approved": True,
                                    "approval_type": "manually_simulated_fixture_input",
                                    "purpose": "one synthetic pre-remediation registry read"}
    owner_inventory = {"owner_approved": True, "approval_type": "manually_simulated_fixture_input",
                       "identity": "reviewed", "repository": "team/model", "approved_actions": []}
    stale = entitlement["declared_age_days"] > entitlement["review_interval_days"]
    mismatch = entitlement["actions"] != owner_inventory["approved_actions"]
    if not (stale and mismatch and owner_inventory["owner_approved"]):
        lab.block("Fixture entitlement review did not produce the expected stale-scope finding")
    lab.check("green", "Review finds aged read grant outside owner-approved fixture inventory",
              stale and mismatch,
              {"declared_age_days": 120, "review_interval_days": 30,
               "owner_approved_actions": [], "declared_actions": ["read"],
               "age_exceeds_interval": stale, "inventory_mismatch": mismatch,
               "approval_type": owner_inventory["approval_type"]})

    remediated = remove_fixture_grant(actual_policy, REPO, entitlement["identity"])
    config_map = {"apiVersion": "v1", "kind": "ConfigMap",
                  "metadata": {"name": "review-zot-config"},
                  "data": {"config.json": json.dumps(remediated, separators=(",", ":"))}}
    lab.kubectl("apply", "-f", "-", payload=json.dumps(config_map))
    readback = _read_config(lab)
    try:
        actual_config = json.loads(readback)
        actual_rules = _policies(actual_config, REPO)
    except (json.JSONDecodeError, KeyError, TypeError):
        lab.block("Remediated repository policy readback was malformed")
    if actual_config != remediated or any("reviewed" in rule.get("users", []) for rule in actual_rules):
        lab.block("Readback still contains the reviewed identity grant")
    if not any(rule.get("users") == ["observer"] and rule.get("actions") == ["read"]
               for rule in actual_rules):
        lab.block("Readback did not preserve the observer read grant")

    # Zot 2.1.23 documents hot reload for htpasswd files, not general policy files;
    # restart applies the ConfigMap policy. The data directory is a PVC and is checked below.
    lab.kubectl("rollout", "restart", "deployment/review-zot")
    _ready(lab, "review-zot")
    reused_claim = json.loads(lab.kubectl("get", "pvc/review-zot-data", "-o", "json").stdout)
    replaced = _registry_uid(lab) != before_uid
    same_claim = reused_claim["metadata"]["uid"] == claim_uid and reused_claim["status"]["phase"] == "Bound"
    after = _probe(lab, "reviewed", stable_digest)
    same_request = all(after.get(key) == before.get(key) for key in ("identity", "method", "path"))
    if after.get("status") != 403:
        lab.block("Post-remediation request was not an authorization denial (401/404 do not pass)")
    lab.check("green", "Same identity and manifest read are denied after policy remediation",
              after.get("status") == 403 and same_request and replaced,
              {"method": after.get("method"), "path": after.get("path"),
               "identity": after.get("identity"), "status": after.get("status"),
               "same_identity_and_request": before.get("identity") == after.get("identity")
               and before.get("method") == after.get("method")
               and before.get("path") == after.get("path"),
               "policy_grant_removed_on_readback": True})

    retained = _probe(lab, "observer", stable_digest)
    if retained.get("status") != 200 or retained.get("digest_matches_expected") is not True:
        lab.block("Independent observer did not retain access to the persistent fixture manifest")
    lab.check("positive", "Independent identity retains same-repository read and persistent data",
              same_claim and retained.get("status") == 200 and retained.get("digest_matches_expected") is True,
              {"method": retained.get("method"), "path": retained.get("path"),
               "status": retained.get("status"), "digest_matches_seed": retained.get("digest_matches_expected"),
               "same_bound_claim_after_registry_rollout": same_claim})

    (lab.evidence / "entitlement-review.json").write_text(json.dumps({
        "control_id": "SAF-K8S-0905-039",
        "scope": {"registry": "Zot 2.1.23 fixture", "repository": "team/model",
                  "primary_identity": "reviewed", "independent_identity": "observer"},
        "review": {"declared_age_days": 120, "review_interval_days": 30,
                    "owner_approved_actions": [], "approval_type": "manually_simulated_fixture_input",
                    "finding": "stale grant not present in owner-approved fixture inventory",
                    "synthetic_pre_remediation_operation_approved": synthetic_operation_approval["approved"],
                    "synthetic_approval_type": synthetic_operation_approval["approval_type"]},
        "operation": {"method": "GET", "path": "/v2/team/model/manifests/stable",
                      "same_identity_and_request": True, "before_status": before["status"],
                      "after_status": after["status"], "observer_status_after": retained["status"],
                      "stable_manifest_digest": stable_digest,
                      "observer_digest_matches_after_rollout": retained["digest_matches_expected"]},
        "policy_readback": {"reviewed_read_grant_absent": True,
                            "observer_read_grant_retained": True},
        "evidence_boundary": "isolated fixture observations; not production or human approval evidence"
    }, indent=2, sort_keys=True) + "\n")
