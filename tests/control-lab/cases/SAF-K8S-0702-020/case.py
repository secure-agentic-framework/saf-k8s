"""Compare extended resource quota keys and declared namespace budgets."""
import json
import time

from fixtures import container, pod, ready

SCOPE = (
    "Kubernetes v1.36.1 server-side admission for synthetic accelerator, CPU, memory, "
    "PVC storage, and Pod, PVC and Service count quotas. The accelerator probes are dry-runs."
)
QUOTA = "accelerator-budget"
GPU = "gpu.vendor.example/units"
NVIDIA = "nvidia.com/gpu"
HARD = {
    f"requests.{GPU}": "1", f"requests.{NVIDIA}": "1",
    "requests.cpu": "100m", "limits.cpu": "200m",
    "requests.memory": "32Mi", "limits.memory": "64Mi",
    "requests.storage": "64Mi", "pods": "1", "persistentvolumeclaims": "1", "services": "1",
}


def workload(name, requests=None, limits=None, device=None, count=None):
    requested = {"cpu": "10m", "memory": "8Mi", **(requests or {})}
    limited = {"cpu": "50m", "memory": "16Mi", **(limits or {})}
    if device:
        requested[device] = limited[device] = count
    return pod(name, [container("inert", resources={"requests": requested, "limits": limited})],
               automountServiceAccountToken=False)


def claim(name, capacity):
    return {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": name},
            "spec": {"storageClassName": "", "accessModes": ["ReadWriteOnce"],
                     "resources": {"requests": {"storage": capacity}}}}


def service(name):
    return {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
            "spec": {"ports": [{"port": 8080, "protocol": "TCP"}]}}


def quota_status(lab, field, expected):
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        status = json.loads(lab.kubectl("get", "resourcequota", QUOTA, "-o", "json").stdout)["status"]
        observed = status.get(field, {})
        if all(observed.get(key) == value for key, value in expected.items()):
            return
        time.sleep(0.5)
    lab.block(f"Quota controller did not report expected {field}")


def dry_run(lab, record):
    return lab.create(record, dry_run=True, allow_failure=True)


def assert_refused(lab, resource, key):
    result = dry_run(lab, resource)
    matched = (result.returncode != 0 and f"exceeded quota: {QUOTA}" in result.stderr
               and f"{key}=" in result.stderr)
    lab.check("green", f"Quota rejects the isolated {key} overage", matched,
              {"quota_key": key, "quota_denial": matched,
               "detail": "" if matched else result.stderr.strip()})


def run(lab):
    candidate = workload("extended-overage", device=GPU, count="2")
    unsupported = f"limits.{GPU}"
    lab.create({"apiVersion": "v1", "kind": "ResourceQuota", "metadata": {"name": QUOTA},
                "spec": {"hard": {unsupported: "1"}}})
    quota_status(lab, "hard", {unsupported: "1"})
    baseline = dry_run(lab, candidate)
    lab.check("red", "A limits-prefixed accelerator quota entry leaves the synthetic request unaccounted",
              baseline.returncode == 0, {"pod_dry_run_admitted": baseline.returncode == 0,
                                         "detail": baseline.stderr.strip()})

    patch = [{"op": "replace", "path": "/spec/hard", "value": HARD}]
    lab.kubectl("patch", "resourcequota", QUOTA, "--type=json", "-p", json.dumps(patch))
    quota_status(lab, "hard", HARD)

    for obj, key in (
        (candidate, f"requests.{GPU}"),
        (workload("nominal-gpu-over", device=NVIDIA, count="2"), f"requests.{NVIDIA}"),
        (workload("cpu-requests-over", requests={"cpu": "110m"}, limits={"cpu": "140m"}), "requests.cpu"),
        (workload("cpu-limits-over", limits={"cpu": "201m"}), "limits.cpu"),
        (workload("memory-requests-over", requests={"memory": "33Mi"}, limits={"memory": "48Mi"}), "requests.memory"),
        (workload("memory-limits-over", limits={"memory": "65Mi"}), "limits.memory"),
        (claim("storage-over", "65Mi"), "requests.storage"),
    ):
        assert_refused(lab, obj, key)

    fitting = dry_run(lab, workload("accelerator-at-budget", device=GPU, count="1"))
    lab.check("positive", "The API admits an accelerator declaration at the quota boundary",
              fitting.returncode == 0, {"admitted": fitting.returncode == 0,
                                        "detail": fitting.stderr.strip()})

    lab.create(workload("bounded-pod"))
    ready(lab, "bounded-pod")
    lab.create(claim("bounded-claim", "16Mi"))
    lab.create(service("bounded-service"))
    quota_status(lab, "used", {"pods": "1", "persistentvolumeclaims": "1", "services": "1",
                               "requests.storage": "16Mi", "requests.cpu": "10m", "requests.memory": "8Mi"})
    for obj, key in ((workload("another-pod"), "pods"), (claim("another-claim", "16Mi"), "persistentvolumeclaims"),
                     (service("another-service"), "services")):
        assert_refused(lab, obj, key)
    pods = json.loads(lab.kubectl("get", "pods", "-o", "json").stdout)["items"]
    ready_names = sorted(item["metadata"]["name"] for item in pods
                         if any(c["type"] == "Ready" and c["status"] == "True"
                                for c in item["status"].get("conditions", [])))
    lab.check("positive", "The sole admitted Pod remains Ready after quota denials",
              len(pods) == 1 and ready_names == ["bounded-pod"],
              {"pod_count": len(pods), "ready_pods": ready_names})
