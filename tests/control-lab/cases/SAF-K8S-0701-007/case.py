"""Exercise a narrow tenant Pod admission boundary for storage workloads."""

import importlib.util
import json
from pathlib import Path

from fixtures import BUSYBOX_IMAGE

SCOPE = (
    "Disposable two-node Kind v1.36.1. Server dry-run compares restrictive Pod Security admission "
    "of exact privilege and hostPath declarations. A nonroot Pod proves real read-only PVC access. "
    "Two bounded ordinary Pods compare scheduling on the exact owned tainted worker. An additive "
    "case-owned ValidatingAdmissionPolicy compares an approved installer identity with a tenant identity "
    "that has the same pods/create RBAC grant, using one harmless restricted Pod and server dry-run denial. "
    "Actual provider privileges, authorization configuration, and supported host controls require separate evidence."
)
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"


def prepare_kind(_lab, temporary):
    config = temporary / "kind.yaml"
    config.write_bytes(Path(__file__).with_name("kind.yaml").read_bytes())
    return config


def pod(name, *, privileged=False, host_path=False, pvc=False, readonly=True, command="sleep 3600"):
    volume = {"name": "storage"}
    mount = {"name": "storage", "mountPath": "/data", "readOnly": readonly}
    if host_path:
        volume["hostPath"] = {"path": "/var/lib/saf-test-fixture", "type": "Directory"}
    elif pvc:
        volume["persistentVolumeClaim"] = {"claimName": "synthetic-storage", "readOnly": readonly}
    else:
        volume["emptyDir"] = {}
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name},
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 65534,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [{
                "name": "workload",
                "image": BUSYBOX_IMAGE,
                "command": ["sh", "-ec", command],
                "volumeMounts": [mount],
                "securityContext": {
                    "allowPrivilegeEscalation": privileged,
                    "capabilities": {"drop": ["ALL"]},
                    "privileged": privileged,
                },
            }],
            "volumes": [volume],
        },
    }


def pvc():
    return {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {"name": "synthetic-storage"},
        "spec": {
            "storageClassName": "standard",
            "accessModes": ["ReadWriteOnce"],
            "resources": {"requests": {"storage": "1Mi"}},
        },
    }


def run(lab):
    probes = (
        ("privileged", pod("privileged-probe", privileged=True), "privileged"),
        ("hostPath", pod("hostpath-probe", host_path=True), "hostPath"),
    )
    for name, candidate, reason in probes:
        baseline = lab.create(candidate, dry_run=True, allow_failure=True)
        lab.check(
            "red",
            f"Unrestricted namespace admits the synthetic {name} storage Pod",
            baseline.returncode == 0,
            {"admitted": baseline.returncode == 0, "detail": baseline.stderr.strip()},
        )

    lab.kubectl(
        "label", "namespace", "saf-test",
        "pod-security.kubernetes.io/enforce=restricted",
        "pod-security.kubernetes.io/enforce-version=v1.36",
        "--overwrite",
    )

    for name, candidate, reason in probes:
        denied = lab.create(candidate, dry_run=True, allow_failure=True)
        detail = denied.stderr.strip()
        matched = denied.returncode != 0 and "violates PodSecurity" in detail and reason in detail
        lab.check(
            "green",
            f"Restricted Pod Security admission rejects the {name} storage Pod",
            matched,
            {"denied": denied.returncode != 0, "expected_reason": reason, "detail": detail},
        )

    lab.create(pvc())
    writer = pod("isolated-pvc-writer", pvc=True, readonly=False,
                 command="printf '%s\\n' synthetic-storage-marker > /data/marker")
    lab.create(writer)
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", "pod/isolated-pvc-writer",
                "--timeout=90s", timeout=100)
    reader = pod("isolated-pvc-reader", pvc=True, command=(
        "test \"$(cat /data/marker)\" = synthetic-storage-marker; "
        "if touch /data/should-not-write 2>/dev/null; then exit 3; fi; "
        "awk '$5==\"/data\" {print $6}' /proc/self/mountinfo; "
        "printf '%s\\n' synthetic-storage-marker"
    ))
    lab.create(reader)
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", "pod/isolated-pvc-reader",
                "--timeout=90s", timeout=100)
    bound = json.loads(lab.kubectl("get", "pvc", "synthetic-storage", "-o", "json").stdout)
    mount, content = lab.kubectl("logs", "isolated-pvc-reader").stdout.strip().splitlines()
    lab.check(
        "positive",
        "Restricted admission allows a nonroot reader of a real bound PVC with a read-only mount",
        bound["status"]["phase"] == "Bound" and "ro" in mount.split(",") and content == "synthetic-storage-marker",
        {"claim_bound": bound["status"]["phase"] == "Bound", "read_only_mount": "ro" in mount.split(","),
         "marker_matches": content == "synthetic-storage-marker"},
    )

    # Additive node-isolation comparison. The node and labels are owned by this
    # disposable Kind cluster; the Pods stay nonroot and nonprivileged.
    node_label = "saf.example/isolated-storage"
    taint_key = "saf.example/isolated-storage"
    driver_namespace = "saf-storage-driver"
    allowed_name = "saf-storage-placement-allowed"
    tenant_name = "saf-storage-placement-tenant"
    node_name = None

    def bounded_pod(name, namespace, *, tolerate):
        spec = {
            "restartPolicy": "Never",
            "activeDeadlineSeconds": 30,
            "terminationGracePeriodSeconds": 1,
            "automountServiceAccountToken": False,
            "serviceAccountName": "default",
            "nodeSelector": {node_label: "true"},
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 65534,
                "runAsGroup": 65534,
                "fsGroup": 65534,
                "fsGroupChangePolicy": "OnRootMismatch",
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [{
                "name": "bounded",
                "image": BUSYBOX_IMAGE,
                "command": ["sh", "-ec", "printf isolated-marker > /data/marker; test \"$(cat /data/marker)\" = isolated-marker"],
                "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                              "limits": {"cpu": "100m", "memory": "32Mi"}},
                "volumeMounts": [{"name": "scratch", "mountPath": "/data"}],
                "securityContext": {
                    "runAsNonRoot": True,
                    "runAsUser": 65534,
                    "runAsGroup": 65534,
                    "allowPrivilegeEscalation": False,
                    "privileged": False,
                    "capabilities": {"drop": ["ALL"]},
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
            }],
            "volumes": [{"name": "scratch", "emptyDir": {"sizeLimit": "1Mi"}}],
        }
        if tolerate:
            spec["tolerations"] = [{
                "key": taint_key,
                "operator": "Equal",
                "value": "true",
                "effect": "NoSchedule",
            }]
        return {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": name, "namespace": namespace},
            "spec": spec,
        }

    try:
        nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
        workers = [item for item in nodes
                   if "node-role.kubernetes.io/control-plane" not in item["metadata"].get("labels", {})]
        expected_worker = f"{lab.cluster}-worker"
        if len(nodes) != 2 or [item["metadata"]["name"] for item in workers] != [expected_worker]:
            lab.block("The isolation profile did not identify the exact owned Kind worker")
        node_name = expected_worker
        lab.kubectl("label", "node", node_name, f"{node_label}=true", "--overwrite")
        lab.kubectl("taint", "node", node_name, f"{taint_key}=true:NoSchedule", "--overwrite")
        lab.kubectl("create", "namespace", driver_namespace)
        lab.kubectl(
            "label", "namespace", driver_namespace,
            "pod-security.kubernetes.io/enforce=restricted",
            "pod-security.kubernetes.io/enforce-version=v1.36",
        )

        allowed = bounded_pod(allowed_name, driver_namespace, tolerate=True)
        lab.kubectl("create", "-n", driver_namespace, "-f", "-", payload=json.dumps(allowed))
        lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{allowed_name}",
                    "-n", driver_namespace, "--timeout=45s", timeout=55)
        allowed_result = json.loads(lab.kubectl(
            "get", "pod", allowed_name, "-n", driver_namespace, "-o", "json").stdout)
        allowed_node = allowed_result["spec"].get("nodeName", "")
        allowed_phase = allowed_result["status"].get("phase")
        actual_container = allowed_result["spec"]["containers"][0]
        restricted = actual_container["securityContext"].get("privileged") is False
        image_pinned = actual_container["image"] == BUSYBOX_IMAGE
        lab.check(
            "positive",
            "Case-approved restricted storage Pod runs on the exact isolated worker",
            allowed_phase == "Succeeded" and allowed_node == node_name and restricted and image_pinned,
            {"phase": allowed_phase, "node_matches_isolated_worker": allowed_node == node_name,
             "nonprivileged": restricted, "image_pinned": image_pinned},
        )

        tenant = bounded_pod(tenant_name, "saf-test", tolerate=False)
        lab.create(tenant)
        lab.kubectl("wait", "--for=condition=PodScheduled=false", f"pod/{tenant_name}",
                    "-n", "saf-test", "--timeout=30s", timeout=40)
        tenant_result = json.loads(lab.kubectl(
            "get", "pod", tenant_name, "-n", "saf-test", "-o", "json").stdout)
        scheduled = tenant_result["spec"].get("nodeName", "")
        conditions = tenant_result["status"].get("conditions", [])
        unschedulable = next((condition for condition in conditions
                              if condition.get("type") == "PodScheduled" and
                              condition.get("status") == "False"), {})
        reason = unschedulable.get("reason", "")
        message = unschedulable.get("message", "")
        worker = json.loads(lab.kubectl("get", "node", node_name, "-o", "json").stdout)
        worker_guard = (
            worker["metadata"]["labels"].get(node_label) == "true"
            and {"key": taint_key, "value": "true", "effect": "NoSchedule"}
                in worker["spec"].get("taints", [])
            and tenant_result["spec"].get("nodeSelector") == {node_label: "true"}
            and all(t.get("key") != taint_key for t in tenant_result["spec"].get("tolerations", []))
        )
        taint_reason = "untolerated taint" in message
        lab.check(
            "negative",
            "Tenant Pod without the storage toleration is unschedulable on the isolated worker",
            not scheduled and reason == "Unschedulable" and taint_reason and worker_guard,
            {"node_assigned": bool(scheduled), "reason": reason, "scheduler_reports_untolerated_taint": taint_reason,
             "exact_worker_taint_and_tenant_selector_verified": worker_guard},
        )
        supplement_path = Path(__file__).with_name("identity_toleration_supplement.py")
        supplement_spec = importlib.util.spec_from_file_location(
            "saf_k8s_0701_007_identity_toleration", supplement_path)
        supplement = importlib.util.module_from_spec(supplement_spec)
        supplement_spec.loader.exec_module(supplement)
        supplement.run(lab, busybox_image=BUSYBOX_IMAGE,
                       node_label=node_label, taint_key=taint_key)
    finally:
        if node_name:
            lab.kubectl("delete", "pod", allowed_name, "-n", driver_namespace,
                        "--ignore-not-found=true", timeout=30, allow_failure=True)
            lab.kubectl("delete", "pod", tenant_name, "-n", "saf-test",
                        "--ignore-not-found=true", timeout=30, allow_failure=True)
            lab.kubectl("delete", "namespace", driver_namespace,
                        "--ignore-not-found=true", "--wait=true", "--timeout=30s", timeout=40, allow_failure=True)
            lab.kubectl("taint", "node", node_name, f"{taint_key}-", timeout=20, allow_failure=True)
            lab.kubectl("label", "node", node_name, f"{node_label}-", timeout=20, allow_failure=True)
