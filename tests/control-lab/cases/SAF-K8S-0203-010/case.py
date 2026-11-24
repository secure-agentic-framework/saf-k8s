"""Verify an actual reduced Kind node image and its retained Kubernetes operation."""

import hashlib
import json
import time
from pathlib import Path

SCOPE = "Compare live stock and APT-free Kind workers, then drain the stock worker and observe the same Deployment become Ready on the approved image."
LOCAL_NODE_VERSION = "v1.36.1"
NODE_IMAGES_FROM_CONFIG = True
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
HERE = Path(__file__).resolve().parent
RECIPE = HERE / "Dockerfile"
SOURCE_SHA = hashlib.sha256(RECIPE.read_bytes()).hexdigest()
VARIANT = "saf-lab-node-minimum:source-" + SOURCE_SHA[:24]
MARKER = "approved reduced node"
UNITS = ("apt-daily.service", "apt-daily.timer", "apt-daily-upgrade.service", "apt-daily-upgrade.timer")
RUNNING_SERVICES = ("kubelet.service", "containerd.service")
PACKAGE_FORMAT = r"-f=${db:Status-Abbrev}\t${binary:Package}\t${Version}\t${Architecture}\n"


def prepare_kind(lab, temporary):
    path = temporary / "kind.yaml"
    path.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  image: {NODE_IMAGE}
- role: worker
  image: {NODE_IMAGE}
  labels:
    saf.example/node-image: stock
- role: worker
  image: {lab.local_node_image}
  labels:
    saf.example/node-image: reduced
""")
    return path


def worker(lab, profile):
    document = lab.kubectl("get", "nodes", "-l", f"saf.example/node-image={profile}", "-o", "json")
    node, = json.loads(document.stdout)["items"]
    return node["metadata"]["name"]


def accounts(getent):
    return {entry[0]: {"uid": int(entry[2]), "gid": int(entry[3]), "shell": entry[6]}
            for entry in (line.split(":") for line in getent.splitlines())}


def verify_image_lineage(lab, candidate):
    stock = json.loads(lab.command("docker", "image", "inspect", "--format", "{{json .}}", NODE_IMAGE).stdout)
    layers = stock["RootFS"]["Layers"]
    return bool(layers) and candidate["RootFS"]["Layers"][:len(layers)] == layers



def inventory(output):
    return {name: {"version": version, "architecture": architecture}
            for status, name, version, architecture in (line.split("\t") for line in output.splitlines())
            if status.startswith("ii")}


ROLLOUT = "node-image-rollout"
DNS_CHECK = (
    "from pathlib import Path; import socket; "
    "socket.getaddrinfo('kubernetes.default.svc.cluster.local', 443); "
    f"assert Path('/fixture/marker').read_text() == {MARKER!r}"
)


def create_deployment(lab):
    labels = {"app": ROLLOUT}
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": ROLLOUT}, "data": {"marker": MARKER}})
    unit = {
        "name": "marker", "image": IMAGE, "command": ["python", "-c", "import time; time.sleep(300)"],
        "readinessProbe": {"exec": {"command": ["python", "-c", DNS_CHECK]}, "periodSeconds": 2, "timeoutSeconds": 4},
        "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]}},
        "resources": {"requests": {"cpu": "5m", "memory": "16Mi"}, "limits": {"cpu": "120m", "memory": "48Mi"}},
    }
    return lab.create({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": ROLLOUT}, "spec": {
        "replicas": 1, "selector": {"matchLabels": labels}, "template": {
            "metadata": {"labels": labels},
            "spec": {"automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [unit], "volumes": [{"name": "fixture", "configMap": {"name": ROLLOUT}}]}}}})


def ready_workload(lab, node):
    deadline = time.monotonic() + 70
    while time.monotonic() < deadline:
        result = lab.kubectl("get", "pods", "-l", f"app={ROLLOUT}", "--field-selector", f"spec.nodeName={node}", "-o", "json")
        for pod in json.loads(result.stdout)["items"]:
            if pod["metadata"].get("deletionTimestamp") is None and any(
                item["type"] == "Ready" and item["status"] == "True" for item in pod.get("status", {}).get("conditions", [])
            ):
                return {"node_name": node, "pod_uid": pod["metadata"]["uid"],
                        "replica_set_uid": pod["metadata"]["ownerReferences"][0]["uid"],
                        "dns_and_configmap_ready": True}
        time.sleep(2)
    lab.kubectl("get", "pods", "-l", f"app={ROLLOUT}", "-o", "wide", allow_failure=True)
    lab.kubectl("get", "events", "--sort-by=.metadata.creationTimestamp", allow_failure=True)
    lab.block(f"No Ready marked workload appeared on the expected disposable worker {node}")


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    stock = worker(lab, "stock")
    node = worker(lab, "reduced")
    lab.kubectl("wait", "--for=condition=Ready", "node/" + stock, "node/" + node, "--timeout=45s", timeout=55)
    stock_tag = lab.command("docker", "image", "inspect", "--format", "{{.Id}}", NODE_IMAGE).stdout.strip()
    stock_image = lab.command("docker", "inspect", "--format", "{{.Image}}", stock).stdout.strip()
    if stock_tag != stock_image:
        lab.block("The baseline worker is not using the pinned stock image")

    original = lab.command("docker", "exec", stock, "dpkg-query", "-W", PACKAGE_FORMAT)
    baseline = inventory(original.stdout)
    stock_accounts = accounts(lab.command("docker", "exec", stock, "getent", "passwd").stdout)
    apt_files = lab.command("docker", "exec", stock, "dpkg-query", "-L", "apt").stdout.splitlines()
    apt_units = sorted({Path(name).name for name in apt_files if "/systemd/system/" in name})
    apt_present = bool(baseline.get("apt"))
    lab.check("red", "The stock image includes the optional package and its exact scheduled maintenance units",
              apt_present and apt_units == sorted(UNITS),
              {"stock_image_apt_present": apt_present, "apt_owned_systemd_units": apt_units})

    candidate = json.loads(lab.command("docker", "image", "inspect", "--format", "{{json .}}", VARIANT).stdout)
    if candidate["Config"]["Labels"].get("org.saf.fixture.node-recipe") != SOURCE_SHA:
        lab.block("The reduced image did not record the reviewed image recipe")
    if not verify_image_lineage(lab, candidate):
        lab.block("The named reduced fixture does not derive from the pinned Kind image layers")
    reviewed = candidate["Id"]
    running = lab.command("docker", "inspect", "--format", "{{.Image}}", node).stdout.strip()
    if reviewed != running or running != lab.local_node_image:
        lab.block("The active Kind node is not using the reviewed reduced image")
    observed = inventory(lab.command("docker", "exec", node, "dpkg-query", "-W", PACKAGE_FORMAT).stdout)
    executable_absent = lab.command("docker", "exec", node, "test", "!", "-e", "/usr/bin/apt-get",
                                    allow_failure=True).returncode == 0
    removed = sorted(set(baseline) - set(observed))
    added = sorted(set(observed) - set(baseline))
    shifted = sorted(key for key in (set(baseline) & set(observed)) if baseline[key] != observed[key])
    lab.check("green", "The effective node image removes the named package without changing the other package versions",
              removed == ["apt"] and not added and not shifted and executable_absent,
              {"selected_package_absent": executable_absent, "removed": removed, "added": added, "changed_versions": shifted})

    missing_units = {}
    for unit in UNITS:
        result = lab.command("docker", "exec", node, "systemctl", "show", "--property=LoadState",
                             "--value", unit)
        missing_units[unit] = result.stdout.strip()
    lab.check("green", "The running node has none of the removed package's scheduled maintenance units",
              set(missing_units.values()) == {"not-found"}, {"load_states": missing_units})
    observed_accounts = accounts(lab.command("docker", "exec", node, "getent", "passwd").stdout)
    same_accounts = stock_accounts == observed_accounts
    lab.check("positive", "The reduction preserves the reviewed image accounts, UID/GID and shell inventory",
              same_accounts and observed_accounts.get("root", {}).get("uid") == 0
              and observed_accounts.get("nobody", {}).get("uid") == 65534,
              {"accounts_unchanged": same_accounts, "observed_account_count": len(observed_accounts)})

    services = lab.command("docker", "exec", node, "systemctl", "is-active", *RUNNING_SERVICES).stdout.split()
    service_states = dict(zip(RUNNING_SERVICES, services))
    lab.check("positive", "The reviewed reduced worker has active kubelet and containerd",
              services == ["active", "active"], {"running_service_states": service_states})

    lab.kubectl("cordon", node)
    deployment_before = create_deployment(lab)["metadata"]["uid"]
    before = ready_workload(lab, stock)
    lab.kubectl("uncordon", node)
    lab.kubectl("drain", stock, "--ignore-daemonsets", "--timeout=45s", timeout=55)
    after = ready_workload(lab, node)
    deployment_after = json.loads(lab.kubectl("get", "deployment", ROLLOUT, "-o", "json").stdout)["metadata"]["uid"]
    drained = json.loads(lab.kubectl("get", "node", stock, "-o", "json").stdout)["spec"].get("unschedulable") is True
    still_missing = lab.command("docker", "exec", node, "test", "!", "-e", "/usr/bin/apt-get",
                                allow_failure=True).returncode == 0
    same_controller = deployment_before == deployment_after and before["replica_set_uid"] == after["replica_set_uid"]
    lab.check("green", "Draining the stock worker replaces its Ready workload on the reduced worker",
              drained and same_controller and before["pod_uid"] != after["pod_uid"] and still_missing,
              {"stock_worker_cordoned": drained, "same_workload_controller": same_controller,
               "new_ready_pod_on_reduced_worker": before["pod_uid"] != after["pod_uid"],
               "apt_still_absent": still_missing})
    (lab.evidence / "node-minimum-observations.json").write_text(json.dumps({
        "source_image": NODE_IMAGE,
        "build_recipe_sha256": SOURCE_SHA,
        "running_variant_image": running,
        "removed_packages": removed,
        "stock_package_inventory": baseline,
        "observed_package_inventory": observed,
        "unchanged_other_package_versions": not added and not shifted,
        "stock_account_inventory": stock_accounts,
        "observed_account_inventory": observed_accounts,
        "removed_unit_load_states": missing_units,
        "running_service_states": service_states,
        "replacement": {"stock_image": stock_image, "stock_worker_cordoned": drained,
                        "deployment_uid_before": deployment_before, "deployment_uid_after": deployment_after,
                        "apt_still_absent": still_missing, "before": before, "after": after},
    }, indent=2) + "\n")
