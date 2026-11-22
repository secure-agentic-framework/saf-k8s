"""Exercise pinned Kueue admission and queue RBAC on an owned Kind cluster."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from uuid import uuid4
from typing import Any


MANIFEST_URL = (
    "https://github.com/kubernetes-sigs/kueue/releases/download/"
    "v0.17.7/manifests.yaml"
)
MANIFEST_SHA256 = "584265b8538b2d84e2baee88368e655b9e3b4338399ef85bac74074d623f967c"
KUEUE_TAG_IMAGE = "registry.k8s.io/kueue/kueue:v0.17.7"
CONTROLLER_IMAGE = 'registry.k8s.io/kueue/kueue:v0.17.7@sha256:de23a924bf8f2df2ff5553a660c1032b7c48ebabd4a551750d0e997819001663'
DEFAULT_JOB_IMAGE = (
    "docker.io/library/busybox:1.37.0@"
    "sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
RECEIPT = "SAF-K8S-0901-006 mock receipt: two workers completed"
TIMEOUT_SECONDS = 60


def _kubectl(lab, *args, input=None, check=True, timeout=40):
    payload = input.decode() if isinstance(input, bytes) else input
    return lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
                       f"kind-{lab.cluster}", f"--request-timeout={timeout - 5}s", *args,
                       payload=payload, allow_failure=not check, timeout=timeout).stdout


def _apply(lab: Any, obj: dict[str, Any]) -> None:
    data = json.dumps(obj, sort_keys=True).encode("utf-8")
    _kubectl(lab, "apply", "-f", "-", input=data)


def _json(lab: Any, *args: str) -> dict[str, Any]:
    return json.loads(_kubectl(lab, *args, "-o", "json"))


def _wait(lab: Any, predicate, description: str, seconds: int = TIMEOUT_SECONDS):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(1)
    lab.block(f"Timed out waiting for {description}; last={last!r}")


def _condition(workload: dict[str, Any], kind: str) -> dict[str, Any] | None:
    return next((c for c in workload.get("status", {}).get("conditions", [])
                 if c.get("type") == kind), None)


def _owned_workload(lab: Any, namespace: str, job: dict[str, Any]):
    workloads = _json(lab, "get", "workloads.kueue.x-k8s.io", "-n", namespace)
    job_uid = job.get("metadata", {}).get("uid")
    for workload in workloads.get("items", []):
        labels = workload.get("metadata", {}).get("labels", {})
        for owner in workload.get("metadata", {}).get("ownerReferences", []):
            if (owner.get("kind") == "Job"
                    and owner.get("uid") == job_uid):
                return workload
        if job_uid and labels.get("kueue.x-k8s.io/job-uid") == job_uid:
            return workload
    return None


def _job(namespace: str, name: str, image: str, cpu: str) -> dict[str, Any]:
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {"kueue.x-k8s.io/queue-name": "tenant-queue"},
        },
        "spec": {
            "suspend": True,
            "activeDeadlineSeconds": 45,
            "parallelism": 2,
            "completions": 2,
            "backoffLimit": 0,
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{
                        "name": "worker",
                        "image": image,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["/bin/sh", "-c", "printf '%s\\n' \"$MOCK_RECEIPT\""],
                        "env": [{"name": "MOCK_RECEIPT", "value": RECEIPT}],
                        "resources": {"requests": {"cpu": cpu}},
                        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]}},
                    }],
                },
            },
        },
    }


def run(lab):
    source = lab.kubeconfig.parent / "kueue-upstream.yaml"
    lab.command("curl", "--no-progress-meter", "--fail", "--location", "--max-time", "50",
                "--output", str(source), MANIFEST_URL, timeout=55)
    source_bytes = source.read_bytes()
    actual = hashlib.sha256(source_bytes).hexdigest()
    if actual != MANIFEST_SHA256:
        lab.block(f"Unexpected Kueue release manifest digest: {actual}")
    original = source_bytes.decode("utf-8")
    if original.count(KUEUE_TAG_IMAGE) != 1:
        lab.block("The Kueue release did not contain exactly one expected controller image")
    installed = source.with_name("kueue-pinned.yaml")
    installed.write_text(original.replace(KUEUE_TAG_IMAGE, CONTROLLER_IMAGE, 1))
    _kubectl(lab, "apply", "--server-side", "-f", str(installed), timeout=110)
    _kubectl(lab, "rollout", "status", "deployment/kueue-controller-manager",
             "-n", "kueue-system", "--timeout=110s", timeout=120)
    deployment = _json(lab, "get", "deployment", "kueue-controller-manager", "-n", "kueue-system")
    controller, = deployment["spec"]["template"]["spec"]["containers"]
    if controller["image"] != CONTROLLER_IMAGE:
        lab.block("The running controller deployment does not use the pinned image")
    suffix = "0901-006"
    namespace = f"saf-kueue-{suffix}"
    cluster_queue = f"saf-cq-{suffix}"
    flavor = f"saf-flavor-{suffix}"
    image = DEFAULT_JOB_IMAGE
    evidence = {"manifest_sha256": actual, "controller_image": CONTROLLER_IMAGE,
                "job_image": image, "namespace": namespace}
    _apply(lab, {"apiVersion": "v1", "kind": "Namespace",
                 "metadata": {"name": namespace,
                              "labels": {"saf-k8s.io/queue-admission": suffix}}})
    flavor_obj = {"apiVersion": "kueue.x-k8s.io/v1beta2", "kind": "ResourceFlavor",
                  "metadata": {"name": flavor}, "spec": {}}
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        result = lab.kubectl("apply", "--server-side", "--dry-run=server", "-f", "-", "-o", "name",
                             payload=json.dumps(flavor_obj), allow_failure=True, timeout=20)
        if result.returncode == 0:
            break
        transient = ("connection refused", "no endpoints available", "context deadline exceeded")
        if not any(reason in result.stderr for reason in transient):
            lab.block(f"Kueue webhook did not admit a valid dry-run ResourceFlavor: {result.stderr.strip()}")
        time.sleep(0.75)
    else:
        lab.block("Kueue admission endpoint remained unavailable after controller rollout")
    _apply(lab, flavor_obj)
    _apply(lab, {
        "apiVersion": "kueue.x-k8s.io/v1beta2", "kind": "ClusterQueue",
        "metadata": {"name": cluster_queue},
        "spec": {
            "namespaceSelector": {"matchLabels": {"saf-k8s.io/queue-admission": suffix}},
            "resourceGroups": [{"coveredResources": ["cpu", "pods"], "flavors": [{
                "name": flavor,
                "resources": [{"name": "cpu", "nominalQuota": "300m"},
                              {"name": "pods", "nominalQuota": "2"}],
            }]}],
        },
    })
    _apply(lab, {
        "apiVersion": "kueue.x-k8s.io/v1beta2", "kind": "LocalQueue",
        "metadata": {"name": "tenant-queue", "namespace": namespace},
        "spec": {"clusterQueue": cluster_queue},
    })

    # Tenant queue administrators can manage LocalQueues only in their
    # namespace. They cannot create cluster-scoped capacity policy.
    _apply(lab, {"apiVersion": "v1", "kind": "ServiceAccount",
                 "metadata": {"name": "tenant-queue-admin", "namespace": namespace}})
    _apply(lab, {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": "tenant-localqueue-admin", "namespace": namespace},
        "rules": [{"apiGroups": ["kueue.x-k8s.io"], "resources": ["localqueues"],
                    "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"]}],
    })
    _apply(lab, {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": "tenant-localqueue-admin", "namespace": namespace},
        "subjects": [{"kind": "ServiceAccount", "name": "tenant-queue-admin",
                      "namespace": namespace}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                    "name": "tenant-localqueue-admin"},
    })
    identity = f"system:serviceaccount:{namespace}:tenant-queue-admin"
    rbac = {
        "localqueue_create_same_namespace": _kubectl(
            lab, "auth", "can-i", "create", "localqueues.kueue.x-k8s.io",
            "-n", namespace, "--as", identity).strip(),
        "localqueue_create_other_namespace": _kubectl(
            lab, "auth", "can-i", "create", "localqueues.kueue.x-k8s.io",
            "-n", "default", "--as", identity, check=False).strip(),
        "clusterqueue_create": _kubectl(
            lab, "auth", "can-i", "create", "clusterqueues.kueue.x-k8s.io",
            "--as", identity, check=False).strip(),
    }
    lab.check("positive", "Kueue queue administration is scoped to the ordinary tenant namespace",
              rbac == {"localqueue_create_same_namespace": "yes",
                       "localqueue_create_other_namespace": "no", "clusterqueue_create": "no"}, rbac)
    evidence["tenant_queue_admin_rbac"] = rbac

    oversized = _job(namespace, "over-quota-two-pod", image, "200m")
    _apply(lab, oversized)
    oversized_job = _json(lab, "get", "job", oversized["metadata"]["name"], "-n", namespace)
    pending = _wait(lab, lambda: (
        workload if (workload := _owned_workload(lab, namespace, oversized_job))
        and (condition := _condition(workload, "QuotaReserved"))
        and condition.get("status") == "False"
        and "cpu" in condition.get("message", "").lower() else None
    ), "native QuotaReserved=False condition")
    if pending.get("spec", {}).get("queueName") != "tenant-queue":
        raise AssertionError(f"over-quota Workload escaped LocalQueue scope: {pending.get('spec')}")
    oversized_now = _json(lab, "get", "job", oversized["metadata"]["name"], "-n", namespace)
    oversized_pods = _json(lab, "get", "pods", "-n", namespace,
                           "-l", f"app={oversized['metadata']['name']}")
    if oversized_now.get("spec", {}).get("suspend") is not True:
        raise AssertionError("over-quota Job was not held suspended")
    if oversized_pods.get("items"):
        raise AssertionError("over-quota suspended Job created child Pods")
    pending_condition = _condition(pending, "QuotaReserved")
    pending_reason = pending_condition.get("reason")
    pending_message = pending_condition.get("message", "").lower()
    lab.check("green", "Kueue leaves the over-quota two-Pod batch held without children",
              pending_reason in ("Pending", "WaitingForQuota") and "quota" in pending_message
              and "cpu" in pending_message and pending["status"].get("admission") is None,
              {"nominal_cpu_millicores": 300, "requested_total_cpu_millicores": 400,
               "cluster_queue_reported_insufficient_cpu_quota": "quota" in pending_message and "cpu" in pending_message,
               "workload_held": True, "job_suspended": True, "child_pod_count": 0})
    evidence["over_quota"] = {
        "job": oversized_now["metadata"]["name"],
        "requests": "2 x 200m CPU = 400m > 300m nominal",
        "workload": pending["metadata"]["name"],
        "quota_reserved": pending_condition,
        "job_suspended": True,
        "child_pod_count": 0,
    }

    admissible = _job(namespace, "admissible-two-pod", image, "100m")
    _apply(lab, admissible)
    admissible_job = _wait(lab, lambda: _json(
        lab, "get", "job", admissible["metadata"]["name"], "-n", namespace),
        "admissible Job creation")
    admitted_workload = _wait(lab, lambda: (
        workload if (workload := _owned_workload(lab, namespace, admissible_job))
        and (condition := _condition(workload, "QuotaReserved"))
        and condition.get("status") == "True" else None
    ), "controller quota reservation for admissible Workload")
    if admitted_workload.get("spec", {}).get("queueName") != "tenant-queue":
        raise AssertionError("admissible Workload was not assigned to the scoped LocalQueue")
    admitted = admitted_workload["status"].get("admission") or {}
    if admitted.get("clusterQueue") != cluster_queue:
        lab.block("Kueue did not reserve the admissible workload from the expected ClusterQueue")
    completed = _wait(lab, lambda: (
        job if (job := _json(lab, "get", "job", admissible["metadata"]["name"], "-n", namespace))
        and any(c.get("type") == "Complete" and c.get("status") == "True"
                for c in job.get("status", {}).get("conditions", [])) else None
    ), "two-Pod Job completion")
    pods = _json(lab, "get", "pods", "-n", namespace,
                 "-l", f"app={admissible['metadata']['name']}")
    pod_items = pods.get("items", [])
    if len(pod_items) != 2 or any(p.get("status", {}).get("phase") != "Succeeded"
                                 for p in pod_items):
        raise AssertionError(f"expected exactly two succeeded child Pods, got {pod_items!r}")
    receipts = []
    for pod in sorted(pod_items, key=lambda item: item["metadata"]["name"]):
        log = _kubectl(lab, "logs", "-n", namespace, pod["metadata"]["name"])
        receipts.append({"pod": pod["metadata"]["name"], "stdout": log})
    lab.check("positive", "Kueue reserves quota and releases the in-quota two-Pod batch",
              completed["spec"].get("suspend", False) is False
              and all(item["stdout"] == RECEIPT + "\n" for item in receipts),
              {"nominal_cpu_millicores": 300, "requested_total_cpu_millicores": 200,
               "quota_reserved_from_expected_cluster_queue": True, "succeeded_child_pods": 2,
               "exact_mock_receipts": all(item["stdout"] == RECEIPT + "\n" for item in receipts)})
    evidence["admissible"] = {
        "workload": admitted_workload["metadata"]["name"],
        "quota_reserved": _condition(admitted_workload, "QuotaReserved"),
        "job_complete": True,
        "succeeded_pods": 2,
        "receipts": receipts,
        "exact_mock_receipt": RECEIPT,
    }
    (lab.evidence / "kueue-admission.json").write_text(json.dumps(evidence, indent=2) + "\n")
