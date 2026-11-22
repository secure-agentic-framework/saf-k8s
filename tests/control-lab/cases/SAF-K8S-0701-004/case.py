"""Check exact Delete and Retain lifecycles for synthetic data inside kind."""
import json
from pathlib import Path
import time

from fixtures import container, pod

NAMESPACE = "saf-test"
PROVISIONER = "rancher.io/local-path"
CLASSIFICATION = "saf-k8s.example/retained-data"
RETAIN_CLASS = "saf-reclaim-retain"
DELETE_CLASS = "saf-reclaim-delete"
MARKER = "synthetic-retention-marker"
SCOPE = (
    "Kubernetes v1.36.1 kind on one disposable node. The bundled local-path "
    "provisioner creates two independent synthetic volumes. Native admission "
    "limits labeled backup claims to the Retain class; both reclaim lifecycles "
    "are inspected. Media sanitization, cloud providers, actual backups and "
    "dual authorization require separate evidence."
)


def get(lab, resource, name):
    reply = lab.kubectl("get", resource, name, "--ignore-not-found", "-o", "json")
    return json.loads(reply.stdout) if reply.stdout.strip() else None


def wait_for_phase(lab, resource, name, phase):
    end = time.monotonic() + 90
    while True:
        obj = get(lab, resource, name)
        actual = obj.get("status", {}).get("phase") if obj else "Absent"
        if actual == phase:
            return obj
        if time.monotonic() >= end:
            lab.block(f"{resource}/{name} was {actual}, expected {phase}")
        time.sleep(0.5)


def storage_class(lab, name, policy):
    lab.create({
        "apiVersion": "storage.k8s.io/v1", "kind": "StorageClass",
        "metadata": {"name": name}, "provisioner": PROVISIONER,
        "volumeBindingMode": "WaitForFirstConsumer", "reclaimPolicy": policy,
    })


def claim(name, class_name, protected=False):
    labels = {CLASSIFICATION: "backup"} if protected else {}
    return {
        "apiVersion": "v1", "kind": "PersistentVolumeClaim",
        "metadata": {"name": name, "labels": labels},
        "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": class_name,
                 "resources": {"requests": {"storage": "1Mi"}}},
    }


def node_probe(lab, path):
    outcome = lab.command("docker", "exec", f"{lab.cluster}-control-plane",
                          "sh", "-c", 'if test -f "$1/marker"; then cat "$1/marker"; '
                          'elif test -e "$1"; then printf "DIRECTORY_ONLY"; '
                          'else printf "ABSENT"; fi', "saf-fixture", path)
    return outcome.stdout.strip()


def provision(lab, resource, expected_policy):
    name = resource["metadata"]["name"]
    lab.create(resource)
    workload = pod(name, [container("writer", command=["sh", "-ec",
                             f"printf '%s\\n' {MARKER} > /fixture/marker"],
                   volumeMounts=[{"name": "fixture", "mountPath": "/fixture"}])],
                   automountServiceAccountToken=False,
                   volumes=[{"name": "fixture", "persistentVolumeClaim": {"claimName": name}}])
    lab.create(workload)
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{name}",
                "--timeout=100s", timeout=110)
    claim_obj = wait_for_phase(lab, "pvc", name, "Bound")
    pv_name = claim_obj["spec"]["volumeName"]
    volume = wait_for_phase(lab, "pv", pv_name, "Bound")
    spec = volume["spec"]
    pod_obj = get(lab, "pod", name)
    path = spec.get("hostPath", {}).get("path")
    expected_path = f"/var/local-path-provisioner/{pv_name}_{NAMESPACE}_{name}"
    if (pod_obj["spec"]["nodeName"] != f"{lab.cluster}-control-plane" or path != expected_path
            or spec["claimRef"]["uid"] != claim_obj["metadata"]["uid"]):
        lab.block("Backing directory or bind identity did not match the owned claim/node")
    marker = node_probe(lab, path)
    lab.check("positive", f"The {expected_policy} fixture binds and writes its marker",
              spec["persistentVolumeReclaimPolicy"] == expected_policy and marker == MARKER,
              {"reclaim_policy": spec["persistentVolumeReclaimPolicy"], "marker_written": marker == MARKER})
    lab.kubectl("delete", "pod", name, "--wait=true", "--timeout=30s")
    lab.kubectl("delete", "pvc", name, "--wait=true", "--timeout=30s")
    return pv_name, path


def run(lab):
    base_class = get(lab, "storageclass", "standard")
    if base_class is None or base_class["provisioner"] != PROVISIONER:
        lab.block("The kind bundled local-path provisioner is required")
    image = lab.kubectl("get", "deployment", "local-path-provisioner", "-n", "local-path-storage",
                        "-o", "jsonpath={.spec.template.spec.containers[0].image}").stdout.strip()
    lab.check("positive", "The bundled local-path provisioner serves the standard StorageClass",
              bool(image), {"provisioner": PROVISIONER, "controller_image": image})
    storage_class(lab, RETAIN_CLASS, "Retain")
    storage_class(lab, DELETE_CLASS, "Delete")
    lab.kubectl("label", "namespace", NAMESPACE, "saf-k8s.example/reclaim-fixture=enabled")

    rejected = claim("backup-declared-delete", DELETE_CLASS, protected=True)
    baseline = lab.create(rejected, dry_run=True, allow_failure=True)
    lab.check("red", "Before policy, admission permits the backup claim's Delete declaration",
              baseline.returncode == 0, {"dry_run_admitted": baseline.returncode == 0})
    lab.apply(Path(__file__).with_name("retention-policy.yaml"))
    deadline = time.monotonic() + 20
    while True:
        denied = lab.create(rejected, dry_run=True, allow_failure=True)
        matches = (denied.returncode != 0 and "(Forbidden)" in denied.stderr
                   and "ValidatingAdmissionPolicy 'saf-k8s-0701-004-retention'" in denied.stderr
                   and "backup claims require the Retain StorageClass" in denied.stderr)
        if matches or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check("green", "The same labeled backup declaration receives the intended Retain policy denial",
              matches, {"denied_by_expected_policy": matches})

    scratch_pv, scratch_path = provision(lab, claim("scratch-data", DELETE_CLASS), "Delete")
    wait_for_phase(lab, "pv", scratch_pv, "Absent")
    deadline = time.monotonic() + 30
    while (path_state := node_probe(lab, scratch_path)) != "ABSENT" and time.monotonic() < deadline:
        time.sleep(0.5)
    lab.check("positive", "Delete removes the scratch PV object and its exact provisioned path",
              path_state == "ABSENT",
              {"pv_absent": True, "path_absent": path_state == "ABSENT"})

    backup_pv, backup_path = provision(lab, claim("backup-data", RETAIN_CLASS, protected=True), "Retain")
    released = wait_for_phase(lab, "pv", backup_pv, "Released")
    observed = node_probe(lab, backup_path)
    lab.check("green", "Retain leaves the Released backup PV and readable synthetic data",
              released["spec"]["persistentVolumeReclaimPolicy"] == "Retain" and observed == MARKER,
              {"pv_phase": released["status"]["phase"], "marker_preserved": observed == MARKER})

    lab.kubectl("delete", "pv", backup_pv, "--wait=true", "--timeout=30s")
    wait_for_phase(lab, "pv", backup_pv, "Absent")
    observed = node_probe(lab, backup_path)
    lab.check("positive", "Deleting the Retain PV object leaves the backing data until lab teardown",
              observed == MARKER, {"pv_absent": True, "marker_preserved": observed == MARKER})
