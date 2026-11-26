"""Live-by-ID probes for a supervisor-owned, disposable cluster run.

This module is not executed by the static test command. The supervisor may run
it through lab.py after choosing an isolated kind cluster.
"""
import json
from pathlib import Path
import time

from fixtures import BUSYBOX_IMAGE


HERE = Path(__file__).parent
SCOPE = (
    "Kubernetes v1.36.1 LimitRange and ResourceQuota admission, an owned Job's declared "
    "memory and Job-controller deadline, synthetic queue and input bounds, and an "
    "aggregate declared-memory ResourceQuota comparison, plus one local HTTP ingest example "
    "for a single emptyDir fixture record. Production queue integration, dataset size, runtime "
    "memory and availability requirements require separate deployed evidence."
)


def pod(name, *, memory_limit="65Mi", request="16Mi"):
    resources = {"requests": {"memory": request}, "limits": {"memory": memory_limit}}
    if memory_limit is None:
        resources["limits"].pop("memory")
    if request is None:
        resources["requests"].pop("memory")
    return {
        "apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
        "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "containers": [{
                "name": "inert", "image": BUSYBOX_IMAGE,
                "command": ["sh", "-c", "exit 0"], "resources": resources,
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]},
                    "runAsNonRoot": True, "runAsUser": 65534,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
            }],
        },
    }


def pvc(name, storage):
    return {
        "apiVersion": "v1", "kind": "PersistentVolumeClaim",
        "metadata": {"name": name},
        "spec": {
            "storageClassName": "", "accessModes": ["ReadWriteOnce"],
            "resources": {"requests": {"storage": storage}},
        },
    }


def server_dry_run(lab, resource):
    return lab.kubectl(
        "create", "-f", "-", "--dry-run=server", "-o", "json",
        payload=json.dumps(resource), allow_failure=True,
    )


def wait_for_storage(lab, amount, count):
    quota_deadline = time.monotonic() + 20
    while time.monotonic() < quota_deadline:
        quota = json.loads(lab.kubectl("get", "resourcequota", "saf-0703-005-storage-budget",
                                       "-o", "json").stdout)
        used = quota.get("status", {}).get("used", {})
        if used.get("requests.storage") == amount and used.get("persistentvolumeclaims") == count:
            return
        time.sleep(0.25)
    lab.block(f"ResourceQuota did not account for {count} synthetic PVCs totaling {amount}")


def queue_job(lab):
    name = "saf-0703-005-queue-model"
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                "data": {filename: (HERE / filename).read_text() for filename in ("bounds.py", "queue_probe.py")}})
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
        "spec": {"backoffLimit": 0, "template": {"spec": {
            "automountServiceAccountToken": False, "restartPolicy": "Never",
            "volumes": [{"name": "fixture", "configMap": {"name": name}}],
            "containers": [{
                "name": "queue", "image": "docker.io/library/python:3.13-slim@sha256:"
                                          "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90",
                "command": ["python", "-B", "/fixture/queue_probe.py"],
                "resources": {"requests": {"memory": "16Mi"}, "limits": {"memory": "32Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                                    "runAsNonRoot": True, "runAsUser": 65534,
                                    "seccompProfile": {"type": "RuntimeDefault"}},
                "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
            }],
        }}},
    })
    lab.kubectl("wait", "--for=condition=Complete", f"job/{name}", "--timeout=80s", timeout=90)
    data = json.loads(lab.kubectl("logs", f"job/{name}").stdout)
    lab.check("green", "The Job rejects full-queue and oversized input and preserves FIFO recovery",
              data == {"queue_full_rejected": True, "oversize_rejected_without_enqueue": True,
                       "retry_after_seconds": 1, "retry_after_completion_accepted": True}, data)


def memory_quota_checks(lab):
    """Compare declared memory sums through API-server admission only."""
    aggregate = pod("saf-0703-005-memory-aggregate", memory_limit="16Mi", request="8Mi")
    first = aggregate["spec"]["containers"][0]
    first["name"] = "bounded-a"
    second = json.loads(json.dumps(first))
    second["name"] = "bounded-b"
    aggregate["spec"]["containers"].append(second)
    baseline = server_dry_run(lab, aggregate)
    admitted_aggregate = json.loads(baseline.stdout) if baseline.returncode == 0 else {}
    requested_mib = sum(int(item["resources"]["requests"]["memory"][:-2])
                        for item in admitted_aggregate.get("spec", {}).get("containers", []))
    limited_mib = sum(int(item["resources"]["limits"]["memory"][:-2])
                      for item in admitted_aggregate.get("spec", {}).get("containers", []))
    lab.check(
        "red", "The exact 16Mi request and 32Mi limit aggregate is admitted before a memory quota",
        baseline.returncode == 0 and requested_mib == 16 and limited_mib == 32,
        {"admitted": baseline.returncode == 0, "requested_memory_mib": requested_mib,
         "limited_memory_mib": limited_mib},
    )

    lab.apply(HERE / "memory-quota.yaml")
    quota_deadline = time.monotonic() + 20
    while True:
        quota = json.loads(lab.kubectl("get", "resourcequota", "saf-0703-005-memory-budget",
                                       "-o", "json").stdout)
        hard = quota.get("status", {}).get("hard", {})
        if hard.get("requests.memory") == "8Mi" and hard.get("limits.memory") == "16Mi":
            break
        if time.monotonic() >= quota_deadline:
            lab.block("The fixture memory ResourceQuota did not become active")
        time.sleep(0.25)

    denied = server_dry_run(lab, aggregate)
    denied_by_quota = (
        denied.returncode != 0
        and "exceeded quota: saf-0703-005-memory-budget" in denied.stderr
        and ("requests.memory" in denied.stderr or "limits.memory" in denied.stderr)
    )
    lab.check(
        "green", "The same otherwise valid aggregate request is refused by the namespace memory quota",
        denied_by_quota,
        {"denied_by_memory_quota": denied_by_quota, "requested_memory_mib": requested_mib,
         "limited_memory_mib": limited_mib},
    )

    lower = server_dry_run(lab, pod("saf-0703-005-memory-under-budget",
                                   memory_limit="8Mi", request="4Mi"))
    admitted_lower = json.loads(lower.stdout) if lower.returncode == 0 else {}
    lower_requested_mib = sum(int(item["resources"]["requests"]["memory"][:-2])
                               for item in admitted_lower.get("spec", {}).get("containers", []))
    lower_limited_mib = sum(int(item["resources"]["limits"]["memory"][:-2])
                            for item in admitted_lower.get("spec", {}).get("containers", []))
    lab.check(
        "positive", "A lower 4Mi request and 8Mi limit remain admissible under the memory quota",
        lower.returncode == 0 and lower_requested_mib == 4 and lower_limited_mib == 8,
        {"admitted": lower.returncode == 0, "requested_memory_mib": lower_requested_mib,
         "limited_memory_mib": lower_limited_mib},
    )


def live_ingest_boundary(lab):
    """Check HTTP status separately from independent emptyDir file readback."""
    import hashlib

    name = "saf-0703-005-ingest"
    client_name = name + "-client"
    image = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
    pod_security = {"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534, "fsGroup": 65534,
                    "seccompProfile": {"type": "RuntimeDefault"}}
    server = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {"app": name}},
              "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                       "terminationGracePeriodSeconds": 1, "securityContext": pod_security,
                       "volumes": [{"name": "fixture", "configMap": {"name": name}},
                                   {"name": "record", "emptyDir": {}}],
                       "containers": [{"name": "api", "image": image,
                         "command": ["python", "-B", "/fixture/ingest_api.py"],
                         "ports": [{"containerPort": 8081, "name": "http"}],
                         "readinessProbe": {"httpGet": {"path": "/healthz", "port": "http"},
                                            "periodSeconds": 1, "timeoutSeconds": 1},
                         "resources": {"requests": {"cpu": "5m", "memory": "16Mi"},
                                       "limits": {"cpu": "100m", "memory": "32Mi"}},
                         "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                             "capabilities": {"drop": ["ALL"]}},
                         "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True},
                                          {"name": "record", "mountPath": "/data"}]}]}}
    client = {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": client_name},
              "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 25,
                       "template": {"spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                         "securityContext": pod_security,
                         "volumes": [{"name": "fixture", "configMap": {"name": name}}],
                         "containers": [{"name": "client", "image": image,
                           "command": ["python", "-B", "/fixture/ingest_client.py"],
                           "resources": {"requests": {"cpu": "5m", "memory": "16Mi"},
                                         "limits": {"cpu": "100m", "memory": "32Mi"}},
                           "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                               "capabilities": {"drop": ["ALL"]}},
                           "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}]}]}}}}

    def local_file_digest_size():
        # Execute an exact read-only Python command in the API Pod. It returns
        # only the record file's size and digest; the file bytes are not printed.
        script = ("import hashlib,json,pathlib; p=pathlib.Path('/data/record'); "
                  "b=p.read_bytes(); print(json.dumps({'size_bytes':len(b),"
                  "'sha256':hashlib.sha256(b).hexdigest()},sort_keys=True))")
        result = lab.kubectl("exec", name, "-c", "api", "--", "python", "-B", "-c", script)
        return json.loads(result.stdout)

    def cleanup_fixture():
        commands = [
            ("delete", "job", client_name, "--ignore-not-found=true", "--wait=true"),
            ("delete", "service", name, "--ignore-not-found=true", "--wait=true"),
            ("delete", "pod", name, "--ignore-not-found=true", "--wait=true"),
            ("delete", "configmap", name, "--ignore-not-found=true", "--wait=true"),
        ]
        failures = []
        for command in commands:
            try:
                result = lab.kubectl(*command, timeout=20, allow_failure=True)
                if result.returncode != 0:
                    failures.append(command[1])
            except Exception:
                failures.append(command[1])
        if failures:
            lab.block("Case-owned ingest fixture cleanup failed for " + ", ".join(failures))

    try:
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                    "data": {"ingest_api.py": (HERE / "ingest_api.py").read_text(),
                             "ingest_client.py": (HERE / "ingest_client.py").read_text()}})
        lab.create(server)
        lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=30s", timeout=35)
        lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
                    "spec": {"type": "ClusterIP", "selector": {"app": name},
                             "ports": [{"name": "http", "port": 8081, "targetPort": "http"}]}})
        before_file = local_file_digest_size()
        lab.create(client)
        lab.kubectl("wait", "--for=condition=Complete", f"job/{client_name}", "--timeout=35s", timeout=40)
        observed = json.loads(lab.kubectl("logs", f"job/{client_name}").stdout)
        after_file = local_file_digest_size()
    except Exception:
        # Best-effort cleanup must not replace the originating setup or API
        # failure with a secondary deletion error.
        try:
            cleanup_fixture()
        except Exception:
            pass
        raise
    cleanup_fixture()

    initial_digest = hashlib.sha256(b"INIT").hexdigest()
    accepted_digest = hashlib.sha256(b"TEST").hexdigest()
    expected_client = {"single_record_id": "fixture-one", "initial_read_verified": True,
                       "accepted_http_status": 202, "accepted_input_bytes": 4,
                       "accepted_readback_verified": True,
                       "accepted_readback_sha256": accepted_digest,
                       "rejected_http_status": 413, "rejected_input_bytes": 5,
                       "rejected_readback_unchanged": True,
                       "rejected_readback_sha256": accepted_digest}
    file_transition = (before_file == {"size_bytes": 4, "sha256": initial_digest}
                       and after_file == {"size_bytes": 4, "sha256": accepted_digest})
    lab.check("positive", "HTTP accepts four inert bytes, rejects five, and an independent file digest confirms only the accepted write",
              observed == expected_client and file_transition,
              {"single_record_id": observed.get("single_record_id"),
               "accepted_http_status": observed.get("accepted_http_status"),
               "accepted_input_bytes": observed.get("accepted_input_bytes"),
               "rejected_http_status": observed.get("rejected_http_status"),
               "rejected_input_bytes": observed.get("rejected_input_bytes"),
               "http_readback_unchanged_after_reject": observed.get("rejected_readback_unchanged"),
               "independent_before_file_size_bytes": before_file.get("size_bytes"),
               "independent_before_file_sha256": before_file.get("sha256"),
               "independent_after_file_size_bytes": after_file.get("size_bytes"),
               "independent_after_file_sha256": after_file.get("sha256"),
               "independent_file_transition_matched": file_transition})


def run(lab):
    oversized_memory = pod("saf-0703-005-memory-over")
    baseline_memory = server_dry_run(lab, oversized_memory)
    lab.check(
        "red", "Without a memory bound, the oversized synthetic Pod reaches admission",
        baseline_memory.returncode == 0,
        {"admitted": baseline_memory.returncode == 0,
         "detail": baseline_memory.stderr.strip()},
    )

    oversized_claim = pvc("saf-0703-005-pvc-over", "9Mi")
    baseline_claim = server_dry_run(lab, oversized_claim)
    lab.check(
        "red", "Without storage bounds, the oversized synthetic PVC reaches admission",
        baseline_claim.returncode == 0,
        {"admitted": baseline_claim.returncode == 0,
         "detail": baseline_claim.stderr.strip()},
    )

    lab.apply(HERE / "limit-range.yaml")
    lab.apply(HERE / "resource-quota.yaml")

    bounded_memory = server_dry_run(lab, pod("saf-0703-005-memory-default", memory_limit=None,
                                              request=None))
    admitted_memory = json.loads(bounded_memory.stdout) if bounded_memory.returncode == 0 else {}
    container = admitted_memory.get("spec", {}).get("containers", [{}])[0]
    requests = container.get("resources", {}).get("requests", {})
    limits = container.get("resources", {}).get("limits", {})
    lab.check(
        "green", "Pod admission defaults omitted memory to the fixed namespace ceiling",
        bounded_memory.returncode == 0 and limits.get("memory") == "32Mi"
        and requests.get("memory") == "16Mi",
        {"admitted": bounded_memory.returncode == 0,
         "memory_request": requests.get("memory"), "memory_limit": limits.get("memory"),
         "detail": bounded_memory.stderr.strip()},
    )

    denied_memory = server_dry_run(lab, oversized_memory)
    lab.check(
        "green", "Pod admission rejects an explicit memory limit above the ceiling",
        denied_memory.returncode != 0 and "maximum memory usage per Container" in denied_memory.stderr,
        {"denied_by_limit_range": denied_memory.returncode != 0
         and "maximum memory usage per Container" in denied_memory.stderr,
         "detail": denied_memory.stderr.strip()},
    )

    denied_claim = server_dry_run(lab, oversized_claim)
    lab.check(
        "green", "PVC admission rejects a claim above the per-claim storage bound",
        denied_claim.returncode != 0 and "maximum storage usage per PersistentVolumeClaim"
        in denied_claim.stderr,
        {"denied_by_limit_range": denied_claim.returncode != 0
         and "maximum storage usage per PersistentVolumeClaim" in denied_claim.stderr,
         "detail": denied_claim.stderr.strip()},
    )

    first_claim = lab.create(pvc("saf-0703-005-pvc-aggregate-first", "8Mi"))
    wait_for_storage(lab, "8Mi", "1")
    second_claim = lab.create(pvc("saf-0703-005-pvc-aggregate-at-bound", "8Mi"))
    wait_for_storage(lab, "16Mi", "2")
    lab.check(
        "positive", "PVC admission permits aggregate requested storage at the namespace quota",
        first_claim["spec"]["resources"]["requests"]["storage"] == "8Mi"
        and second_claim["spec"]["resources"]["requests"]["storage"] == "8Mi",
        {"accounted_total": "16Mi", "admitted_claims": 2},
    )
    third_claim = server_dry_run(lab, pvc("saf-0703-005-pvc-aggregate-over", "1Mi"))
    lab.check(
        "green", "PVC admission rejects aggregate requested storage above the namespace quota",
        third_claim.returncode != 0 and "exceeded quota: saf-0703-005-storage-budget"
        in third_claim.stderr and "requests.storage" in third_claim.stderr,
        {"denied_by_resource_quota": third_claim.returncode != 0
         and "exceeded quota: saf-0703-005-storage-budget" in third_claim.stderr
         and "requests.storage" in third_claim.stderr,
         "detail": third_claim.stderr.strip()},
    )

    permitted_pod = server_dry_run(lab, pod("saf-0703-005-memory-at-bound",
                                            memory_limit="64Mi", request="16Mi"))
    lab.check(
        "positive", "Admission permits the declared memory ceiling",
        permitted_pod.returncode == 0,
        {"admitted": permitted_pod.returncode == 0,
         "detail": permitted_pod.stderr.strip()},
    )
    queue_job(lab)
    lab.apply(HERE / "deadline-job.yaml")
    selector = "batch.kubernetes.io/job-name=saf-0703-005-deadline-probe"
    pod_wait = time.monotonic() + 10
    while True:
        job_pods = json.loads(lab.kubectl("get", "pods", "-l", selector, "-o", "json").stdout)["items"]
        if job_pods or time.monotonic() >= pod_wait:
            break
        time.sleep(0.25)
    lab.kubectl("wait", "--for=condition=Ready", "pod", "-l", selector, "--timeout=14s", timeout=18)
    bounded_specs = [
        all(container.get("resources", {}).get("requests", {}).get("memory") == "16Mi"
            and container.get("resources", {}).get("limits", {}).get("memory") == "32Mi"
            for container in item.get("spec", {}).get("containers", []))
        for item in job_pods
    ]
    lab.check(
        "green", "Job-created Pod is admitted with its fixed memory request and limit",
        bool(job_pods) and all(bounded_specs),
        {"running_job_pods": len(job_pods),
         "all_have_16Mi_request_and_32Mi_limit": bool(job_pods) and all(bounded_specs)},
    )

    name = "saf-0703-005-deadline-probe"
    lab.kubectl("wait", "--for=condition=Failed", f"job/{name}", "--timeout=45s", timeout=50)
    job = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)
    failed = next((condition for condition in job["status"].get("conditions", [])
                   if condition.get("type") == "Failed" and condition.get("status") == "True"), {})
    lab.check("green", "Job controller fails the inert sleeper at its active deadline",
              failed.get("reason") == "DeadlineExceeded" and job["spec"]["activeDeadlineSeconds"] == 20,
              {"reason": failed.get("reason"), "active_deadline_seconds": job["spec"]["activeDeadlineSeconds"]})

    live_ingest_boundary(lab)
    memory_quota_checks(lab)
