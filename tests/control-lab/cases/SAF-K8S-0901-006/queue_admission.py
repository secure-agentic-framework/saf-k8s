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


def _wait_policy_typecheck(lab: Any, name: str, seconds: int = 30) -> None:
    """Wait for the API server's current-generation policy type check, not just POST success."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        policy = _json(lab, "get", "validatingadmissionpolicy", name)
        metadata = policy.get("metadata", {})
        status = policy.get("status", {})
        if (metadata.get("generation") == status.get("observedGeneration")
                and "typeChecking" in status):
            return
        time.sleep(0.5)
    lab.block("Native priority policy type checking did not complete in time")


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
                    "terminationGracePeriodSeconds": 1,
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
    config_marker = "    #waitForPodsReady:"
    if original.count(config_marker) != 1:
        lab.block("Pinned Kueue manifest lacks the expected readiness configuration anchor")
    readiness_config = """    waitForPodsReady:
      timeout: 15s
      blockAdmission: true
      requeuingStrategy:
        backoffBaseSeconds: 60
        backoffMaxSeconds: 60"""
    manifest = original.replace(KUEUE_TAG_IMAGE, CONTROLLER_IMAGE, 1)
    installed.write_text(manifest.replace(config_marker, readiness_config, 1))
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
    worker = admissible["spec"]["template"]["spec"]["containers"][0]
    worker["command"][-1] = "sleep 8; " + worker["command"][-1]
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
    all_ready = _wait(lab, lambda: (
        condition if (workload := _owned_workload(lab, namespace, admissible_job))
        and (condition := _condition(workload, "PodsReady")) and condition["status"] == "True" else None
    ), "Kueue all-Pod readiness for the healthy job")
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
        "all_pods_ready": all_ready,
    }
    evidence["readiness_timeout"] = verify_readiness_timeout(lab, namespace, image)
    evidence["priority_authorization"] = verify_priority_authorization(
        lab, namespace, cluster_queue, image, suffix)
    (lab.evidence / "kueue-admission.json").write_text(json.dumps(evidence, indent=2) + "\n")

def verify_readiness_timeout(lab, namespace, image):
    fixture = _job(namespace, "one-worker-not-ready", image, "100m")
    fixture["spec"]["completionMode"] = "Indexed"
    pod_spec = fixture["spec"]["template"]["spec"]
    worker = pod_spec["containers"][0]
    worker["command"] = ["/bin/sh", "-c", "sleep 45"]
    worker["readinessProbe"] = {
        "exec": {"command": ["/bin/sh", "-c", 'test "$JOB_COMPLETION_INDEX" = 0']},
        "periodSeconds": 1, "failureThreshold": 1,
    }
    name = fixture["metadata"]["name"]
    _apply(lab, fixture)
    job = _json(lab, "get", "job", name, "-n", namespace)

    def one_ready():
        workload = _owned_workload(lab, namespace, job)
        if not workload:
            return None
        ready = _condition(workload, "PodsReady")
        quota = _condition(workload, "QuotaReserved")
        pods = _json(lab, "get", "pods", "-n", namespace, "-l", f"app={name}")["items"]
        if len(pods) != 2 or not all(pod["status"].get("phase") == "Running" for pod in pods):
            return None
        states = {pod["metadata"]["annotations"]["batch.kubernetes.io/job-completion-index"]:
                  next(c["status"] for c in pod["status"]["conditions"] if c["type"] == "Ready")
                  for pod in pods}
        if states != {"0": "True", "1": "False"}:
            return None
        if ready and ready["status"] == "False" and quota and quota["status"] == "True":
            return {"workers": states, "pods_ready": ready, "quota_reserved": quota}
        return None

    before = _wait(lab, one_ready, "a quota-reserved batch with one of two workers Ready", seconds=25)
    lab.check("red", "Kueue observes that the admitted batch never reaches all-Pod readiness",
              before["workers"] == {"0": "True", "1": "False"},
              {"ready_workers": 1, "running_workers": 2, "quota_was_reserved": True})

    def released():
        workload = _owned_workload(lab, namespace, job)
        if not workload:
            return None
        evicted = _condition(workload, "Evicted")
        reservation = _condition(workload, "QuotaReserved")
        current = _json(lab, "get", "job", name, "-n", namespace)
        pods = _json(lab, "get", "pods", "-n", namespace, "-l", f"app={name}")["items"]
        if (evicted and evicted["status"] == "True" and evicted["reason"] == "PodsReadyTimeout"
                and reservation and reservation["status"] == "False"
                and current["spec"].get("suspend") is True and not pods):
            return {"evicted": evicted, "quota_reserved": reservation, "job_suspended": True,
                    "remaining_pods": 0}
        return None

    after = _wait(lab, released, "readiness timeout eviction, suspension and quota release", seconds=30)
    lab.check("green", "Kueue evicts the unready batch, suspends it, removes its Pods and releases quota",
              after["remaining_pods"] == 0 and after["job_suspended"],
              {"reason": after["evicted"]["reason"], "remaining_owned_pods": after["remaining_pods"],
               "quota_released": after["quota_reserved"]["status"] == "False", "job_suspended": True})
    return {"before": before, "after": after}


def verify_priority_authorization(lab, namespace, cluster_queue, image, suffix):
    """Bind Kueue workload priority names at Job admission, then inspect the real Workload."""
    tenant = "priority-tenant"
    tenant_identity = f"system:serviceaccount:{namespace}:{tenant}"
    normal_class = "tenant-normal"
    elevated_class = "platform-high"
    priority_label = "kueue.x-k8s.io/priority-class"
    policy_name = "saf-0901-006-priority-policy"
    binding_name = policy_name + "-binding"
    message = "tenant job must use the approved Kueue priority and no Pod PriorityClass"

    for name, value in ((normal_class, 10), (elevated_class, 1000)):
        _apply(lab, {"apiVersion": "kueue.x-k8s.io/v1beta2", "kind": "WorkloadPriorityClass",
                     "metadata": {"name": name, "labels": {"saf-k8s.io/fixture": suffix}},
                     "value": value, "description": "Fixed synthetic priority authorization fixture"})
    _apply(lab, {"apiVersion": "scheduling.k8s.io/v1", "kind": "PriorityClass",
                 "metadata": {"name": "saf-0901-006-pod-high",
                              "labels": {"saf-k8s.io/fixture": suffix}},
                 "value": 500, "globalDefault": False, "preemptionPolicy": "Never",
                 "description": "Fixed synthetic Pod PriorityClass comparator"})

    _apply(lab, {"apiVersion": "v1", "kind": "ServiceAccount",
                 "metadata": {"name": tenant, "namespace": namespace,
                              "labels": {"saf-k8s.io/fixture": suffix}},
                 "automountServiceAccountToken": True})
    _apply(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                 "metadata": {"name": "priority-tenant-jobs", "namespace": namespace},
                 "rules": [{"apiGroups": ["batch"], "resources": ["jobs"],
                            "verbs": ["create", "get", "patch", "update"]}]})
    _apply(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                 "metadata": {"name": "priority-tenant-jobs", "namespace": namespace},
                 "subjects": [{"kind": "ServiceAccount", "name": tenant,
                               "namespace": namespace}],
                 "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                             "name": "priority-tenant-jobs"}})

    tenant_create = _kubectl(lab, "auth", "can-i", "create", "jobs.batch", "-n", namespace,
                             "--as", tenant_identity, check=False).strip()
    tenant_priorityclass_create = _kubectl(
        lab, "auth", "can-i", "create", "workloadpriorityclasses.kueue.x-k8s.io",
        "--as", tenant_identity, check=False).strip()

    elevated = _job(namespace, "unauthorized-priority-dry-run", image, "10m")
    elevated["metadata"]["labels"][priority_label] = elevated_class
    before_high = _job_create_request(lab, namespace, tenant_identity, elevated, dry_run=True)
    pod_priority = _job(namespace, "pod-priority-dry-run", image, "10m")
    pod_priority["spec"]["template"]["spec"]["priorityClassName"] = "saf-0901-006-pod-high"
    before_pod_priority = _job_create_request(lab, namespace, tenant_identity, pod_priority, dry_run=True)
    missing_priority = _job(namespace, "missing-priority-dry-run", image, "10m")
    before_missing = _job_create_request(lab, namespace, tenant_identity, missing_priority, dry_run=True)
    if (before_high["returncode"] != 0 or before_pod_priority["returncode"] != 0
            or before_missing["returncode"] != 0):
        lab.block("The harmless baseline priority proposals did not reach ordinary API admission")

    policy = {
        "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": policy_name, "labels": {"saf-k8s.io/fixture": suffix}},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {"resourceRules": [{"apiGroups": ["batch"], "apiVersions": ["v1"],
                                                       "operations": ["CREATE", "UPDATE"],
                                                       "resources": ["jobs"], "scope": "Namespaced"}]},
            "validations": [{"expression":
                f"'{priority_label}' in object.metadata.labels && "
                f"object.metadata.labels['{priority_label}'] == '{normal_class}' && "
                "(!has(object.spec.template.spec.priorityClassName) || "
                "object.spec.template.spec.priorityClassName == '')",
                "message": message, "reason": "Forbidden"}],
        },
    }
    _apply(lab, policy)
    _apply(lab, {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
                 "metadata": {"name": binding_name, "labels": {"saf-k8s.io/fixture": suffix}},
                 "spec": {"policyName": policy_name, "validationActions": ["Deny"],
                          "matchResources": {"namespaceSelector": {"matchLabels":
                              {"saf-k8s.io/queue-admission": suffix}}}}})

    # Policy and binding objects can be accepted before their admission cache is
    # ready. First wait for type checking, then poll only this exact harmless
    # rejected proposal until the native Deny action is observable.
    _wait_policy_typecheck(lab, policy_name)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        high_denied = _job_create_request(lab, namespace, tenant_identity, elevated, dry_run=True)
        if high_denied["returncode"] != 0:
            if message not in high_denied["message"]:
                lab.block("Elevated-priority dry run failed for an unexpected reason (details suppressed)")
            break
        time.sleep(0.5)
    else:
        lab.block("The native priority policy did not deny the fixed elevated-priority dry run")

    pod_priority_denied = _job_create_request(lab, namespace, tenant_identity, pod_priority, dry_run=True)
    missing_denied = _job_create_request(lab, namespace, tenant_identity, missing_priority, dry_run=True)
    normal = _job(namespace, "authorized-priority-two-pod", image, "10m")
    normal["metadata"]["labels"][priority_label] = normal_class
    normal_result = _job_create_request(lab, namespace, tenant_identity, normal, dry_run=True)
    if (pod_priority_denied["returncode"] == 0 or message not in pod_priority_denied["message"]
            or missing_denied["returncode"] == 0 or message not in missing_denied["message"]
            or normal_result["returncode"] != 0):
        lab.block("Native priority admission did not enforce the approved named class")

    normal["metadata"]["name"] = "authorized-priority-two-pod"
    normal["metadata"]["labels"]["app"] = normal["metadata"]["name"]
    worker = normal["spec"]["template"]["spec"]["containers"][0]
    worker["command"][-1] = "sleep 2; " + worker["command"][-1]
    _kubectl(lab, "--as", tenant_identity, "create", "-f", "-", input=json.dumps(normal))
    expected_priority_ref = {"group": "kueue.x-k8s.io",
                             "kind": "WorkloadPriorityClass",
                             "name": normal_class}
    job = _wait(lab, lambda: _json(lab, "get", "job", normal["metadata"]["name"], "-n", namespace),
                "authorized tenant Job creation")
    workload = _wait(lab, lambda: (
        current if (current := _owned_workload(lab, namespace, job))
        and current.get("spec", {}).get("priorityClassRef") == expected_priority_ref
        and current.get("spec", {}).get("priority") == 10
        else None
    ), "Kueue Workload with the approved named priority")
    complete = _wait(lab, lambda: (
        current if (current := _json(lab, "get", "job", normal["metadata"]["name"], "-n", namespace))
        and any(condition.get("type") == "Complete" and condition.get("status") == "True"
                for condition in current.get("status", {}).get("conditions", [])) else None
    ), "approved low-resource priority Job completion")

    patch_result = lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "--namespace", namespace, f"--request-timeout=25s", "--as", tenant_identity,
        "patch", "job", normal["metadata"]["name"], "--type=merge", "--dry-run=server", "-o", "json",
        "--patch", json.dumps({"metadata": {"labels": {priority_label: elevated_class}}}),
        timeout=30, allow_failure=True)
    updated_high_denied = patch_result.returncode != 0 and message in patch_result.stderr
    pod_items = _json(lab, "get", "pods", "-n", namespace,
                      "-l", f"app={normal['metadata']['name']}").get("items", [])
    workload_spec = workload.get("spec", {})
    observed_ref = {"queue_name": workload_spec.get("queueName"),
                    "priority_class_ref": workload_spec.get("priorityClassRef"),
                    "priority": workload_spec.get("priority")}
    expected_ref = {"queue_name": "tenant-queue",
                    "priority_class_ref": expected_priority_ref, "priority": 10}
    no_pod_priority = not job.get("spec", {}).get("template", {}).get("spec", {}).get("priorityClassName")
    captured = (observed_ref == expected_ref and no_pod_priority
                and bool(complete) and len(pod_items) == 2
                and all(item.get("status", {}).get("phase") == "Succeeded" for item in pod_items))
    matched = (tenant_create == "yes" and tenant_priorityclass_create == "no"
               and before_high["returncode"] == 0 and before_pod_priority["returncode"] == 0
               and before_missing["returncode"] == 0
               and high_denied["returncode"] != 0 and pod_priority_denied["returncode"] != 0
               and missing_denied["returncode"] != 0
               and normal_result["returncode"] == 0 and updated_high_denied and captured)
    lab.check("positive", "Tenant Jobs can use only the approved Kueue workload priority; higher Kueue and Pod priority fields are denied and the real Workload records the approved value",
              matched,
              {"tenant_can_create_jobs": tenant_create == "yes",
               "tenant_cannot_create_priority_classes": tenant_priorityclass_create == "no",
               "baseline_high_workload_priority_admitted": before_high["returncode"] == 0,
               "baseline_pod_priority_admitted": before_pod_priority["returncode"] == 0,
               "baseline_missing_class_admitted": before_missing["returncode"] == 0,
               "high_workload_priority_denied": high_denied["returncode"] != 0 and message in high_denied["message"],
               "pod_priority_denied": pod_priority_denied["returncode"] != 0 and message in pod_priority_denied["message"],
               "missing_class_denied": missing_denied["returncode"] != 0 and message in missing_denied["message"],
               "approved_normal_class_admitted": normal_result["returncode"] == 0,
               "update_to_high_class_denied": updated_high_denied,
               "observed_real_workload": observed_ref,
               "two_mock_workers_succeeded": len(pod_items) == 2 and all(
                   item.get("status", {}).get("phase") == "Succeeded" for item in pod_items),
               "no_pod_priority_class_on_approved_job": no_pod_priority})
    return {"baseline_high_priority_dry_run": before_high["returncode"] == 0,
            "baseline_pod_priority_dry_run": before_pod_priority["returncode"] == 0,
            "baseline_missing_class_dry_run": before_missing["returncode"] == 0,
            "high_workload_priority_denied": high_denied["returncode"] != 0,
            "pod_priority_denied": pod_priority_denied["returncode"] != 0,
            "missing_class_denied": missing_denied["returncode"] != 0,
            "approved_class": observed_ref,
            "job_complete": bool(complete), "success_pod_count": len(pod_items),
            "update_to_high_class_denied": updated_high_denied}


def _job_create_request(lab, namespace, identity, job, dry_run=False):
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
            "--namespace", namespace, "--request-timeout=25s", "--as", identity,
            "create", "-f", "-", "-o", "json"]
    if dry_run:
        args.append("--dry-run=server")
    response = lab.command(*args, payload=json.dumps(job), timeout=30, allow_failure=True)
    return {"returncode": response.returncode,
            "message": response.stderr if response.returncode else ""}
