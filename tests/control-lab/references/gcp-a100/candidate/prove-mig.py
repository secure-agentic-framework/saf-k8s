"""Capture actual MIG allocation and admission evidence on the owned guest."""

import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
from uuid import uuid4

import mig_admission as admission
from mig_inventory import MigPrecondition, read_inventory, require
from mig_setup import (
    BOOT_ID, RESERVATION, STATE_DIR, device_plugin_matches, digest as structure_digest,
    expected_resources, plugin_state,
)

ROOT = Path(__file__).resolve().parent
NS = "saf-gpu-a100"
RESOURCE = "nvidia.com/mig-1g.5gb"
PODS = ("a100-mig-a", "a100-mig-b")
IMAGE = ("nvcr.io/nvidia/k8s/cuda-sample:vectoradd-cuda12.5.0-ubuntu22.04@"
         "sha256:86c8ab90b657bc74098f068e670d2635799f1fd3695a0dd55fd696d8f9e3d64b")


def command(*args, data=None, check=True, timeout=90):
    return subprocess.run(args, input=data, text=True, capture_output=True, check=check,
                          timeout=timeout, env={**os.environ, "LC_ALL": "C"})


def k(*args, **kwargs):
    return command("/usr/local/bin/k3s", "kubectl", *args, **kwargs)


def create(object_, *, dry=False, check=True):
    extra = ("--dry-run=server",) if dry else ()
    return k("-n", NS, "create", "-f", "-", "-o", "json", *extra,
             data=json.dumps(object_), check=check)


def pod(name, resource, run):
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "labels": {admission.RUN_LABEL: run}},
            "spec": {"restartPolicy": "Never", "runtimeClassName": "nvidia",
                     "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "vector", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                         "command": ["/bin/sh", "-ec", "out=$(/cuda-samples/vectorAdd); case \"$out\" in "
                                     "*\"Test PASSED\"*) echo SAF_A100_MIG_CUDA_PASS;; *) exit 1;; esac; sleep 300"],
                         "resources": {"limits": {resource: "1", "memory": "512Mi", "cpu": "500m"},
                                       "requests": {resource: "1", "memory": "64Mi", "cpu": "25m"}},
                         "securityContext": {"allowPrivilegeEscalation": False,
                                             "capabilities": {"drop": ["ALL"]}}}]}}


def capture_owned(value, owned):
    record = json.loads(value.stdout)
    owned.append((record["kind"].lower(), record["metadata"]["name"], record["metadata"]["uid"]))
    return record


def detach_owned(owned, run):
    for kind, name, uid in reversed(owned):
        out = k("-n", NS, "get", kind, name, "--ignore-not-found", "-o", "json").stdout
        if not out.strip():
            continue
        metadata = json.loads(out)["metadata"]
        require(metadata["uid"] == uid and metadata.get("labels", {}).get(admission.RUN_LABEL) == run,
                "Fixture identity changed during cleanup; review the isolated guest")
        k("-n", NS, "delete", kind, name, "--wait=true", "--timeout=40s", timeout=45)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def verify_placement(node, inventory, node_before, run, owned):
    policy = "saf-a100-mig-" + run
    rejected_pod = "a100-unapproved-placement"
    unapproved = pod(rejected_pod, "nvidia.com/gpu", run)
    before = create(unapproved, dry=True, check=False)
    require(before.returncode == 0, "The whole-GPU dry-run did not pass before the fixture admission policy")
    for resource in admission.objects(NS, policy, run):
        capture_owned(create(resource), owned)
    deadline = time.monotonic() + 20
    while True:
        result = create(unapproved, dry=True, check=False)
        if admission.exact_denial(result, rejected_pod, policy):
            break
        require(result.returncode == 0, "Whole-GPU request failed without the exact named Forbidden decision")
        require(time.monotonic() < deadline, "Expected named denial for the whole-GPU request")
        time.sleep(0.4)
    deadline = time.monotonic() + 15
    while True:
        settings = json.loads(k("get", "validatingadmissionpolicy", policy, "-o", "json").stdout)
        checking = settings.get("status", {}).get("typeChecking")
        if isinstance(checking, dict):
            require(not checking.get("expressionWarnings"), "Policy type checking reported warnings")
            break
        require(time.monotonic() < deadline, "Policy type check status is missing")
        time.sleep(0.4)
    require(not k("-n", NS, "get", "pod", rejected_pod, "--ignore-not-found", "-o", "name").stdout.strip(),
            "A rejected fixture workload unexpectedly exists")

    pods = {}
    for name in PODS:
        pods[name] = capture_owned(create(pod(name, RESOURCE, run)), owned)["metadata"]["uid"]
    allocations = []
    workloads = []
    for name, uid in pods.items():
        k("-n", NS, "wait", f"pod/{name}", "--for=condition=Ready", "--timeout=100s", timeout=110)
        deadline = time.monotonic() + 20
        while True:
            logs = k("-n", NS, "logs", name, "-c", "vector", check=False)
            if logs.returncode == 0 and "SAF_A100_MIG_CUDA_PASS" in logs.stdout.splitlines():
                break
            require(time.monotonic() < deadline, "The scheduled CUDA fixture did not emit its exact success marker")
            time.sleep(0.4)
        workload = json.loads(k("-n", NS, "get", "pod", name, "-o", "json").stdout)
        require(workload["metadata"]["uid"] == uid
                and workload["metadata"]["labels"].get(admission.RUN_LABEL) == run
                and workload["spec"]["nodeName"] == node
                and workload["status"]["phase"] == "Running", "The allocated fixture identity changed")
        container, = workload["spec"]["containers"]
        require(container["image"] == IMAGE and container["resources"]["limits"] ==
                {RESOURCE: "1", "cpu": "500m", "memory": "512Mi"}, "The reviewed fixture image or limits changed")
        raw = command(str(ROOT / "capture" / "podresources-list-linux-amd64"),
                      "--node-name", node, "--namespace", NS, "--pod", name, "--container", "vector",
                      timeout=12).stdout
        captured = json.loads(raw)
        selected, = captured["entries"]
        require(captured["node_name"] == node and (selected["namespace"], selected["pod"], selected["container"],
                selected["resource_name"]) == (NS, name, "vector", RESOURCE), "PodResources membership changed")
        device, = selected["device_ids"]
        require(device in inventory.devices, "The allocated MIG device was absent from the verified inventory")
        after = json.loads(k("-n", NS, "get", "pod", name, "-o", "json").stdout)
        require(after["metadata"]["uid"] == uid and after["status"]["phase"] == "Running",
                "The workload changed while collecting its allocation")
        allocations.append(device)
        workloads.append({"workload_uid_sha256": digest(uid), "device_ref_sha256": digest(device),
                          "resource": RESOURCE, "cuda_confirmed": True})
    require(len(set(allocations)) == 2 and read_inventory(command) == inventory,
            "The assignments are not distinct or the driver layout changed")
    node_after = json.loads(k("get", "node", node, "-o", "json").stdout)
    require(node_before["metadata"]["uid"] == node_after["metadata"]["uid"]
            and node_before["status"]["nodeInfo"]["bootID"] == node_after["status"]["nodeInfo"]["bootID"]
            and expected_resources(node_after), "Node or advertised GPU resources changed")
    return {"schema": "saf-a100-mig-placement-v2", "status": "passed", "hardware_class": "NVIDIA A100",
            "node_uid_sha256": digest(node_after["metadata"]["uid"]), "resource_claims": workloads,
            "whole_gpu_baseline_admitted_dry_run": True, "whole_gpu_request_denied_by_policy": True,
            "whole_gpu_denied_request_absent": True, "fixture_policy_ref": digest(settings["metadata"]["uid"]),
            "distinct_live_mig_assignments": len(set(allocations)),
            "runtime_kubernetes": node_after["status"]["nodeInfo"]["kubeletVersion"],
            "scope": "One A100, two 1g.5gb instances, resource-specific Kubernetes admission and CUDA.",
            "remanence_or_side_channels_measured": False}


def main(out):
    node = socket.gethostname()
    require(os.geteuid() == 0 and re.fullmatch(r"saf-a100-[0-9]{10}", node),
            "Run only on the disposable A100 guest")
    os.umask(0o077)
    out.mkdir(exist_ok=False)
    inventory = read_inventory(command)
    require(not inventory.empty, "Set up two approved MIG instances before the placement proof")
    node_before = json.loads(k("get", "node", node, "-o", "json").stdout)
    require(node_before["status"]["nodeInfo"]["bootID"] == BOOT_ID.read_text().strip()
            and expected_resources(node_before), "The running guest and Kubernetes GPU resources differ")
    require(not k("-n", NS, "get", "pods", "-o", "name").stdout.strip(),
            "The reviewed fixture namespace must be empty")
    boot = node_before["status"]["nodeInfo"]["bootID"]
    reservation = json.loads((STATE_DIR / RESERVATION).read_text())
    require(reservation["node_ref"] == structure_digest(node_before["metadata"]["uid"])
            and reservation["boot_ref"] == structure_digest(boot)
            and reservation["gpu_ref"] == structure_digest(inventory.gpu)
            and reservation["geometry_ref"] == structure_digest((inventory.devices, inventory.instances))
            and device_plugin_matches(plugin_state(), reservation), "The live GPU or plugin differs from approved setup")
    namespace = json.loads(k("get", "namespace", NS, "-o", "json").stdout)["metadata"]
    require(namespace["name"] == NS and namespace["labels"].get("kubernetes.io/metadata.name") == NS,
            "The expected fixture namespace is unavailable")
    owned = []
    run = uuid4().hex[:16]
    try:
        result = verify_placement(node, inventory, node_before, run, owned)
    finally:
        detach_owned(owned, run)
    after = json.loads(k("get", "namespace", NS, "-o", "json").stdout)["metadata"]
    require(after["uid"] == namespace["uid"] and device_plugin_matches(plugin_state(), reservation),
            "The reserved plugin or fixture namespace changed")
    result["fixture_resources_removed"] = True
    result["fixture_namespace_ref"] = digest(namespace["uid"])
    result["geometry_ref"] = reservation["geometry_ref"]
    (out / "mig-placement.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": "passed", "allocations": 2, "resource": RESOURCE}))


if __name__ == "__main__":
    try:
        main(Path(sys.argv[1]))
    except (MigPrecondition, OSError, ValueError, KeyError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        sys.exit(str(exc))
