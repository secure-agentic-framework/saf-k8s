"""Check bounded Kueue admission recovery using one synthetic resource."""
from hashlib import sha256
import json
import time

from fixtures import BUSYBOX_IMAGE

VERSION = "v0.20.6"
RELEASE = f"https://github.com/kubernetes-sigs/kueue/releases/download/{VERSION}/manifests.yaml"
RELEASE_SHA256 = "b5f643595cfe4799b47acd3499f535fb7137af1dd734a5a66ed67a4fe9f9e466"
IMAGE = f"registry.k8s.io/kueue/kueue:{VERSION}"
IMAGE_SHA256 = "20465f0e56a4eed90ec07fa7838866a90f7b6890c0adc84be86aaee307a6744a"
API = "kueue.x-k8s.io/v1beta2"
NAMESPACE = "saf-0703-015"
QUEUE = "resilience"
CLUSTER_QUEUE = "saf-0703-015-cq"
RESOURCE = "cpu"
JOB = "bounded-recovery"
RECOVERY_JOB = "bounded-recovery-replay"
HEALTH = "owned-job-health"

SCOPE = (
    "On Kueue v0.20.6 and Kubernetes v1.36.1 in disposable kind, a finite 10m CPU Job "
    "starts suspended against zero quota. One quota restoration admits the same Workload. "
    "Its Pod runs and exits with a known application failure. After repairing its synthetic "
    "dependency, an identical queued Job completes. Hardware faults, provider autoscaling, "
    "recurring practice, and production training recovery need deployment evidence."
)


def create(lab, resource):
    namespace = resource.get("metadata", {}).get("namespace")
    args = ("-n", namespace) if namespace else ()
    lab.kubectl(*args, "create", "-f", "-", payload=json.dumps(resource))


def install(lab):
    package = lab.kubeconfig.parent / "kueue.yaml"
    lab.command("curl", "--fail", "--silent", "--show-error", "--location", "--max-time", "90",
                RELEASE, "-o", str(package), timeout=100)
    contents = package.read_bytes()
    if sha256(contents).hexdigest() != RELEASE_SHA256:
        lab.block("The Kueue release manifest did not match its publisher digest")
    image_line = f"        image: {IMAGE}\n".encode()
    if contents.count(image_line) != 1:
        lab.block("The release manifest did not contain its expected controller image")
    contents = contents.replace(
        image_line, f"        image: {IMAGE}@sha256:{IMAGE_SHA256}\n".encode())
    package.write_bytes(contents)
    lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                "apply", "--server-side", "-f", str(package), timeout=120)
    lab.kubectl("wait", "--for=condition=available", "deploy/kueue-controller-manager",
                "-n", "kueue-system", "--timeout=150s", timeout=155)


def configure(lab):
    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl("label", "namespace", NAMESPACE, "saf-k8s.example/case=0703-015")
    flavor = {"apiVersion": API, "kind": "ResourceFlavor",
              "metadata": {"name": "synthetic-capacity"}, "spec": {}}
    deadline = time.monotonic() + 40
    while True:
        result = lab.kubectl("create", "-f", "-", "--dry-run=server", payload=json.dumps(flavor),
                             allow_failure=True)
        if result.returncode == 0:
            break
        if "failed calling webhook" not in result.stderr or time.monotonic() >= deadline:
            lab.block(f"Kueue admission readiness: {result.stderr.strip()}")
        time.sleep(0.75)
    create(lab, flavor)
    create(lab, {
        "apiVersion": API, "kind": "ClusterQueue",
        "metadata": {"name": CLUSTER_QUEUE},
        "spec": {
            "namespaceSelector": {"matchLabels": {"saf-k8s.example/case": "0703-015"}},
            "resourceGroups": [{"coveredResources": [RESOURCE], "flavors": [{
                "name": "synthetic-capacity",
                "resources": [{"name": RESOURCE, "nominalQuota": "0"}],
            }]}],
        },
    })
    create(lab, {"apiVersion": API, "kind": "LocalQueue",
                 "metadata": {"name": QUEUE, "namespace": NAMESPACE},
                 "spec": {"clusterQueue": CLUSTER_QUEUE}})
    lab.kubectl("wait", "--for=condition=Active", f"clusterqueue/{CLUSTER_QUEUE}",
                "--timeout=60s", timeout=65)
    lab.kubectl("wait", "--for=condition=Active", f"localqueue/{QUEUE}", "-n", NAMESPACE,
                "--timeout=60s", timeout=65)


def create_job(lab, name):
    create(lab, {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": {"kueue.x-k8s.io/queue-name": QUEUE}},
        "spec": {
            "completions": 1, "parallelism": 1,
            "backoffLimit": 0, "activeDeadlineSeconds": 90,
            "template": {"spec": {
                "restartPolicy": "Never", "automountServiceAccountToken": False,
                "containers": [{"name": "bounded", "image": BUSYBOX_IMAGE,
                                "command": ["sh", "-ec",
                                            "sleep 7; case $(cat /fixture/health) in "
                                            "fail) echo fixture-unavailable; exit 42;; "
                                            "ready) echo fixture-recovered;; *) exit 43;; esac"],
                                "resources": {"requests": {RESOURCE: "10m"},
                                              "limits": {RESOURCE: "20m"}},
                                "volumeMounts": [{"name": "fixture", "mountPath": "/fixture",
                                                  "readOnly": True}]}],
                "volumes": [{"name": "fixture", "configMap": {"name": HEALTH}}],
            }},
        },
    })


def get(lab, kind, name, namespace=None):
    args = ("-n", namespace) if namespace else ()
    result = lab.kubectl(*args, "get", kind, name, "-o", "json", allow_failure=True)
    return None if result.returncode else json.loads(result.stdout)


def condition(workload, kind):
    return next((item for item in workload.get("status", {}).get("conditions", [])
                 if item.get("type") == kind), {})


def owned_workload(lab):
    job = get(lab, "job", JOB, NAMESPACE)
    if job is None:
        return None
    listing = json.loads(lab.kubectl("get", "workloads", "-n", NAMESPACE, "-o", "json").stdout)
    matches = [item for item in listing.get("items", [])
               if any(owner.get("kind") == "Job" and owner.get("uid") == job["metadata"]["uid"]
                      for owner in item.get("metadata", {}).get("ownerReferences", []))]
    return matches[0] if len(matches) == 1 else None


def wait_for(lab, predicate, description, timeout=90):
    deadline = time.monotonic() + timeout
    latest = None
    while time.monotonic() < deadline:
        latest = owned_workload(lab)
        if latest is not None and predicate(latest):
            return latest
        time.sleep(0.5)
    lab.block(f"Timed out waiting for {description}; last Workload={latest}")


def job_terminal(lab, name, target):
    lab.kubectl("-n", NAMESPACE, "wait", f"--for=condition={target}", f"job/{name}",
                "--timeout=95s", timeout=100)
    job = get(lab, "job", name, NAMESPACE)
    uid = job["metadata"]["uid"]
    pods = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pods", "-o", "json").stdout)["items"]
    matching = [item for item in pods if any(
        owner["kind"] == "Job" and owner["uid"] == uid for owner in item["metadata"].get("ownerReferences", [])
    )]
    if len(matching) != 1:
        lab.block(f"Expected one Pod owned by the terminal Job {name}")
    pod = matching[0]
    status = pod["status"]
    terminal = status["containerStatuses"][0]["state"]["terminated"]
    logs = lab.kubectl("-n", NAMESPACE, "logs", pod["metadata"]["name"]).stdout.strip()
    return {"scheduled": bool(pod["spec"].get("nodeName")), "pod_phase": status["phase"],
            "exit_code": terminal["exitCode"], "marker": logs}


def run(lab):
    install(lab)
    configure(lab)
    create(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                 "metadata": {"name": HEALTH, "namespace": NAMESPACE}, "data": {"health": "fail"}})
    create_job(lab, JOB)

    pending = wait_for(
        lab,
        lambda item: condition(item, "QuotaReserved").get("status") == "False"
        and condition(item, "QuotaReserved").get("reason") == "ExceedsMaxQuota"
        and "insufficient quota for cpu" in condition(item, "QuotaReserved").get("message", ""),
        "the owned Workload to reach Kueue's insufficient-quota pending state",
    )
    initial_job = get(lab, "job", JOB, NAMESPACE)
    initial_pods = json.loads(lab.kubectl("get", "pods", "-n", NAMESPACE, "-o", "json").stdout)["items"]
    held = (condition(pending, "Admitted").get("status") != "True"
            and initial_job["spec"].get("suspend") is True and not initial_pods)
    lab.check("red", "Zero queue CPU quota keeps the same finite Job queued and suspended",
              held, {"quota_reserved": False,
                     "pending_reason": condition(pending, "QuotaReserved").get("reason"),
                     "admitted": False,
                     "job_suspended": initial_job["spec"].get("suspend"),
                     "case_pods": len(initial_pods)})

    restored = {"spec": {"resourceGroups": [{"coveredResources": [RESOURCE], "flavors": [{
        "name": "synthetic-capacity", "resources": [{"name": RESOURCE, "nominalQuota": "10m"}],
    }]}]}}
    lab.kubectl("patch", "clusterqueue", CLUSTER_QUEUE, "--type=merge", "-p", json.dumps(restored))
    admitted = wait_for(
        lab,
        lambda item: condition(item, "Admitted").get("status") == "True"
        and condition(item, "QuotaReserved").get("status") == "True",
        "the same queued Workload to reserve quota and become admitted",
    )
    lab.kubectl("-n", NAMESPACE, "wait", "--for=jsonpath={.spec.suspend}=false", f"job/{JOB}",
                "--timeout=40s", timeout=45)
    resumed_job = get(lab, "job", JOB, NAMESPACE)
    same_job = resumed_job["metadata"]["uid"] == initial_job["metadata"]["uid"]
    same_workload = admitted["metadata"]["uid"] == pending["metadata"]["uid"]
    lab.check("green", "Restored quota admits the exact pending Workload and unsuspends the same Job",
              same_job and same_workload and resumed_job["spec"].get("suspend") is False,
              {"same_job": same_job, "same_workload": same_workload, "suspended": resumed_job["spec"].get("suspend")})

    failed = job_terminal(lab, JOB, "Failed")
    lab.check("red", "The admitted Job runs and records the controlled dependency failure",
              failed == {"scheduled": True, "pod_phase": "Failed", "exit_code": 42,
                         "marker": "fixture-unavailable"}, failed)
    lab.kubectl("-n", NAMESPACE, "patch", "configmap", HEALTH, "--type=merge",
                "-p", '{"data":{"health":"ready"}}')
    create_job(lab, RECOVERY_JOB)
    recovered = job_terminal(lab, RECOVERY_JOB, "Complete")
    lab.check("positive", "An identical queued Job completes after the fixture dependency is repaired",
              recovered == {"scheduled": True, "pod_phase": "Succeeded", "exit_code": 0,
                            "marker": "fixture-recovered"}, recovered)
