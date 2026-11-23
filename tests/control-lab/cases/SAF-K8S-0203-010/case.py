"""Verify an actual reduced Kind node image and its retained Kubernetes operation."""

import hashlib
import json
from pathlib import Path

SCOPE = "Compare the pinned stock Kind image to a test-owned variant without APT, then run a fresh Kubernetes workload on the variant."
LOCAL_NODE_VERSION = "v1.36.1"
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
HERE = Path(__file__).resolve().parent
RECIPE = HERE / "Dockerfile"
SOURCE_SHA = hashlib.sha256(RECIPE.read_bytes()).hexdigest()
VARIANT = "saf-lab-node-minimum:source-" + SOURCE_SHA[:24]
MARKER = "approved reduced node"


def inventory(output):
    return dict(tuple(line.split("\t", 1)) for line in output.splitlines() if "\t" in line)


def workload(lab):
    name = "fixture-reduced-node"
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "data": {"marker": MARKER}})
    unit = {"name": "marker", "image": IMAGE, "command": ["python", "-c",
             "from pathlib import Path; print(Path('/fixture/marker').read_text())"],
            "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "5m", "memory": "12Mi"}, "limits": {"cpu": "100m", "memory": "48Mi"}}}
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name}, "spec": {
        "backoffLimit": 0, "template": {"spec": {"automountServiceAccountToken": False, "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [unit], "volumes": [{"name": "fixture", "configMap": {"name": name}}]}}}})
    lab.kubectl("wait", "--for=condition=Complete", "job/" + name, "--timeout=60s", timeout=70)
    return lab.kubectl("logs", "job/" + name).stdout.strip() == MARKER


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    original = lab.command("docker", "run", "--rm", "--network=none", "--entrypoint=dpkg-query", NODE_IMAGE, "-W")
    baseline = inventory(original.stdout)
    apt_present = bool(baseline.get("apt"))
    lab.check("red", "The source node image includes the selected package manager",
              apt_present, {"stock_image_apt_present": apt_present})

    node = f"{lab.cluster}-control-plane"
    candidate = json.loads(lab.command("docker", "image", "inspect", "--format", "{{json .}}", VARIANT).stdout)
    if candidate["Config"]["Labels"].get("org.saf.fixture.node-recipe") != SOURCE_SHA:
        lab.block("The reduced image did not record the reviewed image recipe")
    reviewed = candidate["Id"]
    running = lab.command("docker", "inspect", "--format", "{{.Image}}", node).stdout.strip()
    if reviewed != running:
        lab.block("The active Kind node is not using the reviewed reduced image")
    observed = inventory(lab.command("docker", "exec", node, "dpkg-query", "-W").stdout)
    executable_absent = lab.command("docker", "exec", node, "test", "!", "-e", "/usr/bin/apt-get",
                                    allow_failure=True).returncode == 0
    removed = sorted(set(baseline) - set(observed))
    added = sorted(set(observed) - set(baseline))
    shifted = sorted(key for key in (set(baseline) & set(observed)) if baseline[key] != observed[key])
    lab.check("green", "The effective node image removes the named package without changing the other package versions",
              removed == ["apt"] and not added and not shifted and executable_absent,
              {"selected_package_absent": executable_absent, "removed": removed, "added": added, "changed_versions": shifted})

    services = lab.command("docker", "exec", node, "systemctl", "is-active", "kubelet", "containerd").stdout.split()
    started = workload(lab)
    lab.check("positive", "The reduced node retains the required runtime and executes a fresh Kubernetes workload",
              services == ["active", "active"] and started, {"required_services_active": services == ["active", "active"],
                                                             "fresh_workload_completed": started})
    (lab.evidence / "node-minimum-observations.json").write_text(json.dumps({
        "source_image": NODE_IMAGE, "running_variant_image": running, "removed_packages": removed,
        "unchanged_other_package_versions": not added and not shifted, "fresh_workload_completed": started,
        "production_image_baseline_tested": False,
    }, indent=2) + "\n")
