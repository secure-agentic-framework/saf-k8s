"""Run Kueue cohort admission and fair-sharing reclamation on synthetic jobs."""
from hashlib import sha256
from decimal import Decimal, InvalidOperation
import json
import re
import time

from fixtures import BUSYBOX_IMAGE

VERSION = "v0.20.6"
RELEASE = f"https://github.com/kubernetes-sigs/kueue/releases/download/{VERSION}/manifests.yaml"
RELEASE_SHA256 = "b5f643595cfe4799b47acd3499f535fb7137af1dd734a5a66ed67a4fe9f9e466"
IMAGE = f"registry.k8s.io/kueue/kueue:{VERSION}"
IMAGE_SHA256 = "20465f0e56a4eed90ec07fa7838866a90f7b6890c0adc84be86aaee307a6744a"
API = "kueue.x-k8s.io/v1beta2"
RESOURCE = "example.com/virtual-gpu"
READY_QUEUE = "ready-queue"
READY_CLUSTER_QUEUE = "ready-cq"
READY_JOB = "ready-pair"
TEAMS = ("team-a", "team-b")
JOB_OWNERS = {"a-baseline": "team-a", "a-borrowed": "team-a", "b-demand": "team-b"}
SCOPE = (
    "Kueue v0.20.6 controller with Fair Sharing and two single-unit quotas, "
    "on disposable kind Kubernetes v1.36.1. Three owned Kubernetes Jobs request "
    "only an unallocated synthetic resource. Kueue admission and reclamation "
    "are inspected, including the recovered nominal unit and queued overage. An "
    "additive two-Pod Job compares suspended quota shortage with full quota "
    "admission and creation of both unassigned Pods. This covers quota-based "
    "all-or-nothing admission. A separate tiny CPU-only two-Pod Job passes through "
    "its exact Kueue queue, reaches both Pod Ready and Workload PodsReady, then completes. "
    "A separate same-cohort CPU and memory fixture captures exact cohort reclamation victim and "
    "preemptor UIDs and reasons, then verifies recovery of the same victim Job and Workload "
    "with a new Ready Pod after exact preemptor deletion. It observes the pinned controller reason "
    "InCohortReclamation. A final additive three-ClusterQueue CPU fixture changes only the peer "
    "queue fair-sharing weight between pending control and an exact InCohortFairSharing preemption. "
    "It uses 100m/100m/300m nominal CPU quotas, 100m baseline and victim requests, and a 400m peer "
    "request; the donor quota and victim's 100m borrowing are checked before comparison. Weight is "
    "1 in control and 10 in comparison. This bounded controller-path test is not sustained fairness, "
    "actual accelerator placement or gang recovery. Access control and production integrations "
    "require separate evidence."
)


def create(lab, resource):
    namespace = resource["metadata"].get("namespace")
    arguments = ("-n", namespace) if namespace else ()
    lab.kubectl(*arguments, "create", "-f", "-", payload=json.dumps(resource))


def install(lab):
    package = lab.kubeconfig.parent / "kueue.yaml"
    lab.command("curl", "--fail", "--silent", "--show-error", "--location", "--max-time", "90",
                RELEASE, "-o", str(package), timeout=100)
    contents = package.read_bytes()
    if sha256(contents).hexdigest() != RELEASE_SHA256:
        lab.block("The official release manifest did not match its publisher digest")
    image = f"        image: {IMAGE}\n".encode()
    if contents.count(image) != 1:
        lab.block("The release manifest did not include its expected exact controller image")
    declaration = b"    #fairSharing:\n    #  preemptionStrategies: [LessThanOrEqualToFinalShare, LessThanInitialShare]\n"
    settings = b"    fairSharing:\n      preemptionStrategies: [LessThanOrEqualToFinalShare, LessThanInitialShare]\n"
    if contents.count(declaration) != 1:
        lab.block("The release manifest did not include the expected Fair Sharing configuration")
    manifest = contents.replace(image, f"        image: {IMAGE}@sha256:{IMAGE_SHA256}\n".encode())
    package.write_bytes(manifest.replace(declaration, settings))
    lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                "apply", "--server-side", "-f", str(package), timeout=120)
    deployment = "deploy/kueue-controller-manager"
    lab.kubectl("wait", "--for=condition=available", deployment, "-n", "kueue-system",
                "--timeout=150s", timeout=155)

    lab.check("positive", "The release manifest digest and pinned controller image are retained",
              True, {"release": VERSION, "manifest_digest": RELEASE_SHA256, "image_digest": IMAGE_SHA256})


def configure_queues(lab):
    flavor = {"apiVersion": API, "kind": "ResourceFlavor",
              "metadata": {"name": "virtual-capacity"}, "spec": {}}
    end = time.monotonic() + 40
    while True:
        result = lab.kubectl("create", "-f", "-", "--dry-run=server", payload=json.dumps(flavor),
                             allow_failure=True)
        if result.returncode == 0:
            break
        if "failed calling webhook" not in result.stderr or time.monotonic() >= end:
            lab.block(f"Kueue admission readiness: {result.stderr.strip()}")
        time.sleep(0.75)
    create(lab, flavor)
    for team in TEAMS:
        create(lab, {"apiVersion": "v1", "kind": "Namespace",
                     "metadata": {"name": team, "labels": {"saf-k8s.example/team": team}}})
        create(lab, {
            "apiVersion": API, "kind": "ClusterQueue", "metadata": {"name": f"{team}-cq"},
            "spec": {"namespaceSelector": {"matchLabels": {"saf-k8s.example/team": team}},
                     "cohortName": "virtual-capacity",
                     "resourceGroups": [{"coveredResources": [RESOURCE],
                                         "flavors": [{"name": "virtual-capacity",
                                                      "resources": [{"name": RESOURCE, "nominalQuota": "1"}]}]}],
                     "preemption": {"reclaimWithinCohort": "Never", "withinClusterQueue": "Never"},
                     "fairSharing": {"weight": "1"}},
        })
        create(lab, {"apiVersion": API, "kind": "LocalQueue",
                     "metadata": {"name": "virtual", "namespace": team},
                     "spec": {"clusterQueue": f"{team}-cq"}})
        lab.kubectl("wait", "--for=condition=Active", f"clusterqueue/{team}-cq",
                    "--timeout=60s", timeout=65)
        lab.kubectl("wait", "--for=condition=Active", "localqueue/virtual", "-n", team,
                    "--timeout=60s", timeout=65)


def job(lab, name):
    team = JOB_OWNERS[name]
    create(lab, {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": team, "labels": {"kueue.x-k8s.io/queue-name": "virtual"}},
        "spec": {"suspend": True, "backoffLimit": 0, "template": {"spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "containers": [{"name": "bounded", "image": BUSYBOX_IMAGE,
                            "command": ["sleep", "15"],
                            "resources": {"requests": {RESOURCE: "1"}, "limits": {RESOURCE: "1"}}}],
        }}},
    })


def objects(lab, command):
    args = command.split()
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def observation(lab):
    out = {}
    for team in TEAMS:
        records = objects(lab, f"get workloads -n {team}")["items"]
        for record in records:
            names = [item["name"] for item in record["metadata"].get("ownerReferences", [])
                     if item["kind"] == "Job"]
            if len(names) != 1 or JOB_OWNERS.get(names[0]) != team:
                continue
            status = record.get("status", {})
            out[names[0]] = {
                "admitted": status.get("admission") is not None and any(
                    cond["type"] == "Admitted" and cond["status"] == "True"
                    for cond in status.get("conditions", [])),
                "reservation_denied": any(cond["type"] == "QuotaReserved" and cond["status"] == "False"
                                          and cond.get("reason") == "WaitingForQuota"
                                          and "insufficient unused quota" in cond.get("message", "")
                                          for cond in status.get("conditions", [])),
            }
    return out


def wait(lab, expected, description, *, pending=None):
    end = time.monotonic() + 85
    while True:
        states = observation(lab)
        if (all(name in states and states[name]["admitted"] == present for name, present in expected.items())
                and (pending is None or states.get(pending, {}).get("reservation_denied"))):
            return states
        if time.monotonic() >= end:
            lab.block(f"{description}. Controller status: {states}")
        time.sleep(0.75)


def observe_borrowing(lab):
    end = time.monotonic() + 45
    while True:
        status = objects(lab, "get clusterqueue team-a-cq").get("status", {})
        share = status.get("fairSharing", {}).get("weightedShare", 0)
        actual = next((entry for flavor in status.get("flavorsReservation", [])
                       for entry in flavor.get("resources", []) if entry.get("name") == RESOURCE), {})
        if status.get("reservingWorkloads") == 2 and actual.get("borrowed") == "1" and share > 0:
            return {"reservations": 2, "borrowed_units": actual["borrowed"], "weighted_share_positive": True}
        if time.monotonic() >= end:
            lab.block(f"ClusterQueue status did not account for the two reservations: {status}")
        time.sleep(0.5)


def run_fairshare(lab):
    install(lab)
    configure_queues(lab)
    job(lab, "a-baseline")
    wait(lab, {"a-baseline": True}, "Team A could not reserve its nominal unit")
    job(lab, "a-borrowed")
    wait(lab, {"a-baseline": True, "a-borrowed": True}, "Team A could not borrow idle capacity")
    job(lab, "b-demand")
    red = wait(lab, {"a-baseline": True, "a-borrowed": True, "b-demand": False},
               "Team B did not reach the no-reclamation quota boundary", pending="b-demand")
    borrowed = observe_borrowing(lab)
    lab.check("red", "At full quota with reclamation disabled, team B remains pending while team A borrows",
              red["b-demand"]["reservation_denied"],
              {"team_a": borrowed, "team_b_quota_pending": red["b-demand"]["reservation_denied"]})

    lab.kubectl("patch", "clusterqueue", "team-b-cq", "--type=merge",
                "-p", '{"spec":{"preemption":{"reclaimWithinCohort":"Any"}}}')
    green = wait(lab, {"a-baseline": True, "a-borrowed": False, "b-demand": True},
                 "The waiting Job did not replace team A's borrowing under fair sharing")
    lab.check("green", "Enabling reclamation admits the same waiting Job and releases the borrowed unit",
              True, {name: state["admitted"] for name, state in green.items()})
    unrelated = [item for team in TEAMS for item in objects(lab, f"get pods -n {team}")["items"]
                 if item.get("spec", {}).get("nodeName")]
    lab.check("positive", "Both queues keep one admission while no synthetic Pod has a bound node",
              green["a-baseline"]["admitted"] and green["b-demand"]["admitted"] and not unrelated,
              {"team_a_retained_nominal": True, "team_b_reclaimed_nominal": True, "bound_pods": len(unrelated)})


def _gang_observation(lab):
    job_resource = json.loads(lab.kubectl("get", "job", "gang-pair", "-n", "gang-team",
                                         "-o", "json").stdout)
    uid = job_resource["metadata"]["uid"]
    candidates = json.loads(lab.kubectl("get", "workloads", "-n", "gang-team",
                                        "-o", "json").stdout)["items"]
    owned = [candidate for candidate in candidates if any(
        owner.get("uid") == uid and owner.get("kind") == "Job" and owner.get("controller") is True
        for owner in candidate["metadata"].get("ownerReferences", []))]
    if len(owned) != 1:
        return None
    workload = owned[0]
    status = workload.get("status", {})
    conditions = status.get("conditions", [])
    admitted = status.get("admission") is not None and any(
        item.get("type") == "Admitted" and item.get("status") == "True"
        for item in conditions)
    waiting_for_quota = any(
        item.get("type") == "QuotaReserved" and item.get("status") == "False"
        and item.get("reason") == "ExceedsMaxQuota"
        and RESOURCE in item.get("message", "")
        and "maximum capacity (1)" in item.get("message", "")
        for item in conditions)
    pods = json.loads(lab.kubectl("get", "pods", "-n", "gang-team",
                                  "-l", "batch.kubernetes.io/job-name=gang-pair",
                                  "-o", "json").stdout)["items"]
    return {"admitted": admitted, "waiting_for_quota": waiting_for_quota,
            "job_suspended": job_resource.get("spec", {}).get("suspend") is True,
            "pod_count": len(pods),
            "all_unassigned": all(not pod.get("spec", {}).get("nodeName") for pod in pods),
            "all_unschedulable": len(pods) == 2 and all(any(
                condition.get("type") == "PodScheduled"
                and condition.get("status") == "False"
                and condition.get("reason") == "Unschedulable"
                for condition in pod.get("status", {}).get("conditions", []))
                for pod in pods)}


def _wait_gang(lab, predicate, description, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        observed = _gang_observation(lab)
        if observed is not None and predicate(observed):
            return observed
        time.sleep(0.75)
    lab.block(f"Timed out waiting for {description}; last observation={observed}")


def run_gang_candidate(lab):
    """Show Kueue quota-based all-or-nothing Job admission with two tiny Pods."""
    gang_namespace = {"apiVersion": "v1", "kind": "Namespace",
                      "metadata": {"name": "gang-team",
                                   "labels": {"saf-k8s.example/team": "gang-team"}}}
    create(lab, gang_namespace)
    cluster_queue = {
        "apiVersion": API, "kind": "ClusterQueue", "metadata": {"name": "gang-cq"},
        "spec": {
            "namespaceSelector": {"matchLabels": {"saf-k8s.example/team": "gang-team"}},
            "cohortName": "gang-cohort",
            "resourceGroups": [{"coveredResources": [RESOURCE],
                                 "flavors": [{"name": "virtual-capacity",
                                              "resources": [{"name": RESOURCE,
                                                             "nominalQuota": "1"}]}]}],
            "preemption": {"reclaimWithinCohort": "Never", "withinClusterQueue": "Never"},
            "fairSharing": {"weight": "1"},
        },
    }
    create(lab, cluster_queue)
    create(lab, {"apiVersion": API, "kind": "LocalQueue",
                 "metadata": {"name": "gang-queue", "namespace": "gang-team"},
                 "spec": {"clusterQueue": "gang-cq"}})
    lab.kubectl("wait", "--for=condition=Active", "clusterqueue/gang-cq",
                "--timeout=60s", timeout=65)
    lab.kubectl("wait", "--for=condition=Active", "localqueue/gang-queue", "-n", "gang-team",
                "--timeout=60s", timeout=65)

    create(lab, {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": "gang-pair", "namespace": "gang-team",
                     "labels": {"kueue.x-k8s.io/queue-name": "gang-queue"}},
        "spec": {"suspend": True, "parallelism": 2, "completions": 2,
                 "backoffLimit": 0,
                 "template": {"spec": {
                     "restartPolicy": "Never", "automountServiceAccountToken": False,
                     "containers": [{"name": "bounded", "image": BUSYBOX_IMAGE,
                                     "command": ["sleep", "15"],
                                     "resources": {"requests": {RESOURCE: "1"},
                                                   "limits": {RESOURCE: "1"}}}],
                 }}}})

    red = _wait_gang(lab, lambda obs: (not obs["admitted"] and obs["waiting_for_quota"]
                                        and obs["job_suspended"] and obs["pod_count"] == 0),
                     "two-pod gang remains wholly queued below its two-unit quota")
    lab.check("red", "With only one synthetic unit, Kueue leaves the two-pod Job suspended with no Pods",
              red["waiting_for_quota"] and red["job_suspended"] and red["pod_count"] == 0,
              {"admitted": red["admitted"], "quota_wait": red["waiting_for_quota"],
               "job_suspended": red["job_suspended"], "created_pods": red["pod_count"]})

    lab.kubectl("patch", "clusterqueue", "gang-cq", "--type=merge", "-p",
                '{"spec":{"resourceGroups":[{"coveredResources":["example.com/virtual-gpu"],'
                '"flavors":[{"name":"virtual-capacity","resources":[{"name":"example.com/virtual-gpu",'
                '"nominalQuota":"2"}]}]}]}}')
    green = _wait_gang(lab, lambda obs: (obs["admitted"] and not obs["job_suspended"]
                                          and obs["pod_count"] == 2 and obs["all_unassigned"]
                                          and obs["all_unschedulable"]),
                       "both gang Pods are created after the full two-unit reservation")
    lab.check("green", "After quota reaches two, Kueue admits the Job and both Pods exist; synthetic GPU requests keep them unassigned",
              green["admitted"] and not green["job_suspended"] and green["pod_count"] == 2
              and green["all_unassigned"] and green["all_unschedulable"],
              {"admitted": green["admitted"], "job_suspended": green["job_suspended"],
               "created_pods": green["pod_count"], "all_pods_unassigned": green["all_unassigned"],
               "all_pods_unschedulable_for_unallocated_resource": green["all_unschedulable"]})


def _ready_pair_observation(lab):
    job_resource = json.loads(lab.kubectl("get", "job", READY_JOB, "-n", "gang-team",
                                         "-o", "json", timeout=20).stdout)
    uid = job_resource["metadata"]["uid"]
    workloads = json.loads(lab.kubectl("get", "workloads", "-n", "gang-team", "-o", "json",
                                      timeout=20).stdout)["items"]
    owned_workloads = [workload for workload in workloads if any(
        owner.get("uid") == uid and owner.get("kind") == "Job" and owner.get("controller") is True
        for owner in workload["metadata"].get("ownerReferences", []))]
    if len(owned_workloads) != 1:
        return None
    workload = owned_workloads[0]
    status = workload.get("status", {})
    conditions = status.get("conditions", [])
    admitted = any(item.get("type") == "Admitted" and item.get("status") == "True"
                   for item in conditions)
    workload_ready = any(item.get("type") == "PodsReady" and item.get("status") == "True"
                         for item in conditions)
    pods = json.loads(lab.kubectl("get", "pods", "-n", "gang-team",
                                  "-l", f"batch.kubernetes.io/job-name={READY_JOB}",
                                  "-o", "json", timeout=20).stdout)["items"]
    owned_pods = [pod for pod in pods if any(
        owner.get("uid") == uid and owner.get("kind") == "Job" and owner.get("controller") is True
        for owner in pod["metadata"].get("ownerReferences", []))]
    every_pod_ready = (len(owned_pods) == 2 and all(
        pod.get("status", {}).get("phase") == "Running"
        and any(condition.get("type") == "Ready" and condition.get("status") == "True"
                for condition in pod.get("status", {}).get("conditions", []))
        for pod in owned_pods))
    admission = status.get("admission") or {}
    job_ready = {
        "job_unsuspended": job_resource.get("spec", {}).get("suspend") is not True,
        "owned_workload_admitted": admitted,
        "exact_local_queue": workload.get("spec", {}).get("queueName") == READY_QUEUE,
        "exact_cluster_queue": admission.get("clusterQueue") == READY_CLUSTER_QUEUE,
        "exactly_two_job_owned_pods": len(owned_pods) == 2,
        "both_pods_running_and_ready": every_pod_ready,
        "workload_pods_ready_condition": workload_ready,
    }
    return job_ready


def _wait_ready_pair(lab):
    deadline = time.monotonic() + 60
    last = None
    while time.monotonic() < deadline:
        last = _ready_pair_observation(lab)
        if last and all(last.values()):
            return last
        time.sleep(0.5)
    lab.block(f"The exact CPU Job did not reach workload-wide Ready: {last}")


def run_cpu_readiness_candidate(lab):
    """Run a two-Pod low-resource Job through a Kueue queue to Ready and completion."""
    create(lab, {
        "apiVersion": API, "kind": "ClusterQueue", "metadata": {"name": READY_CLUSTER_QUEUE},
        "spec": {
            "namespaceSelector": {"matchLabels": {"saf-k8s.example/team": "gang-team"}},
            "resourceGroups": [{"coveredResources": ["cpu", "memory"],
                                "flavors": [{"name": "virtual-capacity",
                                             "resources": [{"name": "cpu", "nominalQuota": "100m"},
                                                           {"name": "memory", "nominalQuota": "128Mi"}]}]}],
            "preemption": {"reclaimWithinCohort": "Never", "withinClusterQueue": "Never"},
            "fairSharing": {"weight": "1"},
        },
    })
    create(lab, {"apiVersion": API, "kind": "LocalQueue",
                 "metadata": {"name": READY_QUEUE, "namespace": "gang-team"},
                 "spec": {"clusterQueue": READY_CLUSTER_QUEUE}})
    lab.kubectl("wait", "--for=condition=Active", f"clusterqueue/{READY_CLUSTER_QUEUE}",
                "--timeout=60s", timeout=65)
    lab.kubectl("wait", "--for=condition=Active", f"localqueue/{READY_QUEUE}", "-n", "gang-team",
                "--timeout=60s", timeout=65)

    create(lab, {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": READY_JOB, "namespace": "gang-team",
                     "labels": {"kueue.x-k8s.io/queue-name": READY_QUEUE}},
        "spec": {"suspend": True, "parallelism": 2, "completions": 2,
                 "backoffLimit": 0, "activeDeadlineSeconds": 30,
                 "template": {"spec": {
                     "restartPolicy": "Never", "automountServiceAccountToken": False,
                     "containers": [{"name": "bounded", "image": BUSYBOX_IMAGE,
                                     "command": ["sleep", "10"],
                                     "readinessProbe": {"exec": {"command": ["sh", "-c", "test -r /proc/1/status"]},
                                                        "periodSeconds": 1, "timeoutSeconds": 1,
                                                        "failureThreshold": 3},
                                     "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                                   "limits": {"cpu": "50m", "memory": "32Mi"}},
                                     "securityContext": {"allowPrivilegeEscalation": False,
                                                         "runAsNonRoot": True, "runAsUser": 65534,
                                                         "capabilities": {"drop": ["ALL"]},
                                                         "seccompProfile": {"type": "RuntimeDefault"}}}],
                 }}}})

    ready = _wait_ready_pair(lab)
    lab.check("positive", "The exact Kueue queue admits the CPU Job and both owned Pods become Ready",
              all(ready.values()), ready)
    lab.kubectl("wait", "--for=condition=complete", f"job/{READY_JOB}", "-n", "gang-team",
                "--timeout=35s", timeout=40)
    job_after = json.loads(lab.kubectl("get", "job", READY_JOB, "-n", "gang-team", "-o", "json",
                                      timeout=20).stdout)
    workload = json.loads(lab.kubectl("get", "workloads", "-n", "gang-team", "-o", "json",
                                     timeout=20).stdout)["items"]
    job_uid = job_after["metadata"]["uid"]
    owned = [item for item in workload if any(
        owner.get("uid") == job_uid and owner.get("kind") == "Job" and owner.get("controller") is True
        for owner in item["metadata"].get("ownerReferences", []))]
    finished = (len(owned) == 1 and any(
        condition.get("type") == "Finished" and condition.get("status") == "True"
        for condition in owned[0].get("status", {}).get("conditions", [])))
    completed = job_after.get("status", {}).get("succeeded") == 2
    ready_captured = all(ready.values())
    lab.check("positive", "The same two-Pod Workload completes after its Ready state was observed",
              completed and finished and ready_captured,
              {"job_completed_two_pods": completed, "workload_finished_condition": finished,
               "ready_state_observed_before_completion": ready_captured,
               "failed_pod_count": job_after.get("status", {}).get("failed", 0)})


FS_RECOVERY_COHORT = "recovery-cohort"
FS_RECOVERY_TEAMS = ("recovery-team-a", "recovery-team-b")
FS_VICTIM_BASELINE = "recovery-a-baseline"
FS_VICTIM = "recovery-a-borrowed"
FS_PREEMPTOR = "recovery-b-demand"
FS_CPU = "100m"
FS_MEMORY = "32Mi"


def _fs_recovery_job_template(namespace, name, priority_class=None):
    labels = {"kueue.x-k8s.io/queue-name": "virtual",
              "saf-k8s.example/fixture": "0703-007-fairshare-recovery"}
    if priority_class:
        labels["kueue.x-k8s.io/priority-class"] = priority_class
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": namespace,
                     "labels": labels},
        "spec": {"suspend": True, "parallelism": 1, "completions": 1,
                 "backoffLimit": 0, "activeDeadlineSeconds": 240,
                 "template": {"metadata": {"labels": {"saf-k8s.example/fixture": "0703-007-fairshare-recovery"}},
                              "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                                       "terminationGracePeriodSeconds": 1,
                                       "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                           "seccompProfile": {"type": "RuntimeDefault"}},
                                       "containers": [{"name": "bounded", "image": BUSYBOX_IMAGE,
                                                       "imagePullPolicy": "IfNotPresent",
                                                       "command": ["sleep", "180"],
                                                       "resources": {"requests": {"cpu": FS_CPU,
                                                                                  "memory": FS_MEMORY},
                                                                     "limits": {"cpu": FS_CPU,
                                                                                "memory": "64Mi"}},
                                                       "securityContext": {"allowPrivilegeEscalation": False,
                                                                           "readOnlyRootFilesystem": True,
                                                                           "capabilities": {"drop": ["ALL"]}}}]}}},
    }


def _fs_json_if_exists(lab, *args):
    result = lab.kubectl(*args, "--ignore-not-found", "-o", "json")
    if not result.stdout.strip():
        return None
    return json.loads(result.stdout)


def _fs_owned_workload(lab, namespace, job_obj):
    if not job_obj:
        return None
    uid = job_obj.get("metadata", {}).get("uid")
    records = json.loads(lab.kubectl("get", "workloads", "-n", namespace, "-o", "json").stdout)["items"]
    owned = [item for item in records if any(
        owner.get("kind") == "Job" and owner.get("apiVersion") == "batch/v1"
        and owner.get("controller") is True and owner.get("uid") == uid
        for owner in item.get("metadata", {}).get("ownerReferences", []))]
    return owned[0] if len(owned) == 1 else None


def _fs_workload_by_uid(lab, namespace, workload_uid):
    records = json.loads(lab.kubectl("get", "workloads", "-n", namespace, "-o", "json").stdout)["items"]
    return next((item for item in records
                 if item.get("metadata", {}).get("uid") == workload_uid), None)


def _fs_owned_pods(lab, namespace, job_obj):
    if not job_obj:
        return []
    uid = job_obj.get("metadata", {}).get("uid")
    pods = json.loads(lab.kubectl("get", "pods", "-n", namespace, "-o", "json").stdout)["items"]
    return [pod for pod in pods if any(
        owner.get("kind") == "Job" and owner.get("apiVersion") == "batch/v1"
        and owner.get("controller") is True and owner.get("uid") == uid
        for owner in pod.get("metadata", {}).get("ownerReferences", []))]


def _fs_condition(workload, kind):
    return next((item for item in (workload or {}).get("status", {}).get("conditions", [])
                 if item.get("type") == kind), None)


def _fs_admitted(workload, cq):
    return bool(workload and workload.get("status", {}).get("admission", {}).get("clusterQueue") == cq
                and (_fs_condition(workload, "Admitted") or {}).get("status") == "True")


def _fs_ready_pod(pods):
    return next((pod for pod in pods if pod.get("status", {}).get("phase") == "Running"
                 and any(item.get("type") == "Ready" and item.get("status") == "True"
                         for item in pod.get("status", {}).get("conditions", []))), None)


def _fs_recovery_snapshot(lab):
    snapshot = {}
    for namespace, name in ((FS_RECOVERY_TEAMS[0], FS_VICTIM_BASELINE),
                            (FS_RECOVERY_TEAMS[0], FS_VICTIM),
                            (FS_RECOVERY_TEAMS[1], FS_PREEMPTOR)):
        job_obj = _fs_json_if_exists(lab, "get", "job", name, "-n", namespace)
        workload = _fs_owned_workload(lab, namespace, job_obj) if job_obj else None
        pods = _fs_owned_pods(lab, namespace, job_obj) if job_obj else []
        snapshot[name] = {"job": job_obj, "workload": workload, "pods": pods}
    return snapshot


def _fs_wait(lab, predicate, description, seconds=90):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        last = _fs_recovery_snapshot(lab)
        if predicate(last):
            return last
        time.sleep(0.75)
    lab.block(f"Timed out waiting for {description}; last snapshot={last!r}")


def _fs_cq_borrowed(lab):
    cq = objects(lab, "get clusterqueue recovery-team-a-cq")
    resources = {resource.get("name"): resource
                 for flavor in cq.get("status", {}).get("flavorsReservation", [])
                 for resource in flavor.get("resources", [])}
    return cq, {name: resources.get(name, {}).get("borrowed") for name in ("cpu", "memory")}


def _fs_create_job(lab, namespace, name, priority_class=None):
    create(lab, _fs_recovery_job_template(namespace, name, priority_class))


def run_fairshare_preemption_recovery_candidate(lab):
    """Check cross-ClusterQueue quota reclamation and Pod recovery."""
    raw = {"cohort": FS_RECOVERY_COHORT, "resources": {"cpu": FS_CPU, "memory": FS_MEMORY},
           "snapshots": []}

    def retain(step, **values):
        raw["snapshots"].append({"step": step, **values})
        (lab.evidence / "fairshare-preemption-recovery-raw.json").write_text(
            json.dumps(raw, indent=2, sort_keys=True) + "\n")

    for team in FS_RECOVERY_TEAMS:
        create(lab, {"apiVersion": "v1", "kind": "Namespace",
                     "metadata": {"name": team,
                                  "labels": {"saf-k8s.example/team": team,
                                             "saf-k8s.example/fixture": "0703-007-fairshare-recovery"}}})
    for team in FS_RECOVERY_TEAMS:
        cq_name = f"{team}-cq"
        create(lab, {
            "apiVersion": API, "kind": "ClusterQueue", "metadata": {"name": cq_name},
            "spec": {"namespaceSelector": {"matchLabels": {"saf-k8s.example/team": team}},
                     "cohortName": FS_RECOVERY_COHORT,
                     "resourceGroups": [{"coveredResources": ["cpu", "memory"],
                                         "flavors": [{"name": "virtual-capacity",
                                                      "resources": [{"name": "cpu", "nominalQuota": FS_CPU},
                                                                    {"name": "memory", "nominalQuota": "128Mi"}]}]}],
                     "preemption": {"reclaimWithinCohort": "Never", "withinClusterQueue": "Never"},
                     "fairSharing": {"weight": "1"}},
        })
        create(lab, {"apiVersion": API, "kind": "LocalQueue",
                     "metadata": {"name": "virtual", "namespace": team},
                     "spec": {"clusterQueue": cq_name}})
        lab.kubectl("wait", "--for=condition=Active", f"clusterqueue/{cq_name}",
                    "--timeout=60s", timeout=65)
        lab.kubectl("wait", "--for=condition=Active", "localqueue/virtual", "-n", team,
                    "--timeout=60s", timeout=65)

    baseline_priority = "recovery-baseline-high"
    create(lab, {"apiVersion": API, "kind": "WorkloadPriorityClass",
                 "metadata": {"name": baseline_priority}, "value": 100,
                 "description": "Fixed baseline priority for fair-share victim selection"})

    _fs_create_job(lab, FS_RECOVERY_TEAMS[0], FS_VICTIM_BASELINE, baseline_priority)
    baseline = _fs_wait(lab, lambda s: _fs_admitted(s[FS_VICTIM_BASELINE]["workload"],
                                                     "recovery-team-a-cq")
                        and _fs_ready_pod(s[FS_VICTIM_BASELINE]["pods"]),
                        "the baseline CPU Job to reserve and run")
    baseline_job = baseline[FS_VICTIM_BASELINE]["job"]
    baseline_workload = baseline[FS_VICTIM_BASELINE]["workload"]
    baseline_pod = _fs_ready_pod(baseline[FS_VICTIM_BASELINE]["pods"])
    if (baseline_workload.get("spec", {}).get("priorityClassRef") != {
            "group": "kueue.x-k8s.io", "kind": "WorkloadPriorityClass",
            "name": baseline_priority}
            or baseline_workload.get("spec", {}).get("priority") != 100):
        lab.block("The baseline did not record the exact approved higher WorkloadPriorityClass")

    _fs_create_job(lab, FS_RECOVERY_TEAMS[0], FS_VICTIM)
    borrowed_state = _fs_wait(lab, lambda s: _fs_admitted(s[FS_VICTIM]["workload"],
                                                          "recovery-team-a-cq")
                              and _fs_ready_pod(s[FS_VICTIM]["pods"]),
                              "the second team A Job to borrow and run")
    victim_job = borrowed_state[FS_VICTIM]["job"]
    victim_workload = borrowed_state[FS_VICTIM]["workload"]
    victim_pod = _fs_ready_pod(borrowed_state[FS_VICTIM]["pods"])
    if victim_workload.get("spec", {}).get("priority", 0) >= baseline_workload["spec"]["priority"]:
        lab.block("The intended lower-priority borrowed Workload is not below the baseline")
    cq, borrowed = _fs_cq_borrowed(lab)
    if (borrowed.get("cpu") != FS_CPU
            or borrowed.get("memory") not in (None, "0", "0m", "0Mi")):
        lab.block(f"Team A did not show 100m CPU borrowing without memory borrowing: {borrowed!r}")

    _fs_create_job(lab, FS_RECOVERY_TEAMS[1], FS_PREEMPTOR)
    held = _fs_wait(lab, lambda s: (
        bool(s[FS_PREEMPTOR]["workload"])
        and (_fs_condition(s[FS_PREEMPTOR]["workload"], "QuotaReserved") or {}).get("status") == "False"
        and (_fs_condition(s[FS_PREEMPTOR]["workload"], "QuotaReserved") or {}).get("reason") == "WaitingForQuota"
        and _fs_admitted(s[FS_VICTIM]["workload"], "recovery-team-a-cq")
        and _fs_ready_pod(s[FS_VICTIM]["pods"])
        and _fs_ready_pod(s[FS_VICTIM_BASELINE]["pods"])),
        "team B's exact CPU Workload to wait behind team A's borrowed reservation")
    preemptor_job = held[FS_PREEMPTOR]["job"]
    preemptor_workload = held[FS_PREEMPTOR]["workload"]
    if preemptor_job is None or preemptor_workload is None:
        lab.block("The waiting peer Job or its exact owner Workload was absent")
    preemptor_job_uid = preemptor_job["metadata"]["uid"]
    preemptor_workload_uid = preemptor_workload["metadata"]["uid"]
    retain("victim_ready_preemptor_waiting", baseline_job=baseline_job,
           baseline_workload=baseline_workload, victim_job=victim_job,
           victim_workload=victim_workload, victim_ready_pod=victim_pod,
           preemptor_job=preemptor_job, preemptor_workload=preemptor_workload,
           team_a_clusterqueue=cq, borrowed_resources=borrowed, waiting_state=held)
    lab.check("positive", "The exact borrowed victim and baseline CPU/memory Jobs are Ready while the peer waits",
              _fs_ready_pod(held[FS_VICTIM]["pods"]) is not None
              and _fs_ready_pod(held[FS_VICTIM_BASELINE]["pods"]) is not None
              and held[FS_VICTIM_BASELINE]["job"]["metadata"]["uid"] == baseline_job["metadata"]["uid"]
              and held[FS_VICTIM_BASELINE]["workload"]["metadata"]["uid"] == baseline_workload["metadata"]["uid"]
              and _fs_ready_pod(held[FS_VICTIM_BASELINE]["pods"])["metadata"]["uid"] == baseline_pod["metadata"]["uid"]
              and held[FS_VICTIM_BASELINE]["workload"].get("spec", {}).get("priority") == 100
              and victim_workload.get("spec", {}).get("priority", 0) < 100
              and held[FS_PREEMPTOR]["workload"] is not None
              and borrowed.get("cpu") == FS_CPU
              and borrowed.get("memory") in (None, "0", "0m", "0Mi"),
              {"victim_ready": True, "baseline_ready": True, "baseline_priority_higher": True,
               "baseline_pod_identity_fixed": True,
               "peer_waiting": True, "victim_borrows_100m_cpu_only": True,
               "memory_remains_within_nominal": True})

    lab.kubectl("patch", "clusterqueue", "recovery-team-b-cq", "--type=merge", "-p",
                '{"spec":{"preemption":{"reclaimWithinCohort":"Any","withinClusterQueue":"Never"}}}')
    evicted = _fs_wait(lab, lambda s: (
        s[FS_VICTIM]["job"] is not None
        and s[FS_VICTIM]["job"].get("metadata", {}).get("uid") == victim_job["metadata"]["uid"]
        and s[FS_VICTIM]["workload"] is not None
        and s[FS_VICTIM]["workload"].get("metadata", {}).get("uid") == victim_workload["metadata"]["uid"]
        and (_fs_condition(s[FS_VICTIM]["workload"], "Evicted") or {}).get("status") == "True"
        and (_fs_condition(s[FS_VICTIM]["workload"], "Evicted") or {}).get("reason") == "Preempted"
        and (_fs_condition(s[FS_VICTIM]["workload"], "Preempted") or {}).get("status") == "True"
        and (_fs_condition(s[FS_VICTIM]["workload"], "Preempted") or {}).get("reason") == "InCohortReclamation"
        and not s[FS_VICTIM]["pods"]
        and s[FS_VICTIM_BASELINE]["job"] is not None
        and s[FS_VICTIM_BASELINE]["workload"] is not None
        and s[FS_VICTIM_BASELINE]["job"].get("metadata", {}).get("uid") == baseline_job["metadata"]["uid"]
        and s[FS_VICTIM_BASELINE]["workload"].get("metadata", {}).get("uid") == baseline_workload["metadata"]["uid"]
        and _fs_ready_pod(s[FS_VICTIM_BASELINE]["pods"]) is not None
        and _fs_ready_pod(s[FS_VICTIM_BASELINE]["pods"])["metadata"]["uid"] == baseline_pod["metadata"]["uid"]
        and s[FS_PREEMPTOR]["job"] is not None
        and s[FS_PREEMPTOR]["workload"] is not None
        and s[FS_PREEMPTOR]["job"].get("metadata", {}).get("uid") == preemptor_job_uid
        and s[FS_PREEMPTOR]["workload"].get("metadata", {}).get("uid") == preemptor_workload_uid
        and _fs_admitted(s[FS_PREEMPTOR]["workload"], "recovery-team-b-cq")
        and _fs_ready_pod(s[FS_PREEMPTOR]["pods"]) is not None),
        "the exact borrowed Job to be evicted by cohort reclamation", seconds=120)
    evicted_workload = evicted[FS_VICTIM]["workload"]
    preempted_condition = _fs_condition(evicted_workload, "Preempted")
    condition_message = (preempted_condition or {}).get("message", "")
    live_preemptor_job = evicted[FS_PREEMPTOR]["job"]
    live_preemptor_workload = evicted[FS_PREEMPTOR]["workload"]
    uid_slots = re.search(
        r"\(UID: ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}), "
        r"JobUID: ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\)",
        condition_message)
    references_preemptor = bool(uid_slots
                                and uid_slots.group(1) == preemptor_workload_uid
                                and uid_slots.group(2) == preemptor_job_uid)
    retain("cohort_reclamation_preemption", victim_job=evicted[FS_VICTIM]["job"],
           victim_workload=evicted_workload, victim_pods=evicted[FS_VICTIM]["pods"],
           preemptor_job=live_preemptor_job, preemptor_workload=live_preemptor_workload,
           preempted_condition=preempted_condition, preemptor_uid_slots=uid_slots.groups() if uid_slots else None,
           preemptor_uids_in_reason=references_preemptor, preemptor_pods=evicted[FS_PREEMPTOR]["pods"],
           baseline_job=evicted[FS_VICTIM_BASELINE]["job"],
           baseline_workload=evicted[FS_VICTIM_BASELINE]["workload"],
           baseline_pod=_fs_ready_pod(evicted[FS_VICTIM_BASELINE]["pods"]))
    lab.check("green", "Kueue cohort reclamation preempts the exact borrowed Workload for the exact peer Workload",
              evicted_workload["metadata"]["uid"] == victim_workload["metadata"]["uid"]
              and evicted[FS_VICTIM]["job"]["metadata"]["uid"] == victim_job["metadata"]["uid"]
              and (_fs_condition(evicted_workload, "Evicted") or {}).get("reason") == "Preempted"
              and (_fs_condition(evicted_workload, "Preempted") or {}).get("reason") == "InCohortReclamation"
              and live_preemptor_job["metadata"]["uid"] == preemptor_job_uid
              and live_preemptor_workload["metadata"]["uid"] == preemptor_workload_uid
              and _fs_admitted(live_preemptor_workload, "recovery-team-b-cq")
              and references_preemptor
              and evicted[FS_VICTIM_BASELINE]["job"]["metadata"]["uid"] == baseline_job["metadata"]["uid"]
              and evicted[FS_VICTIM_BASELINE]["workload"]["metadata"]["uid"] == baseline_workload["metadata"]["uid"]
              and _fs_ready_pod(evicted[FS_VICTIM_BASELINE]["pods"])["metadata"]["uid"] == baseline_pod["metadata"]["uid"],
              {"same_victim_job_and_workload": True, "victim_reason_preempted": True,
               "cohort_reclamation_reason": True, "baseline_job_and_workload_unchanged": True,
               "baseline_pod_stayed_ready": True, "preemptor_admitted": True,
               "preemptor_uids_in_victim_reason": references_preemptor})

    preemptor_uid = preemptor_job_uid
    delete_options = {"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Foreground",
                      "preconditions": {"uid": preemptor_uid}}
    uri = f"/apis/batch/v1/namespaces/{FS_RECOVERY_TEAMS[1]}/jobs/{FS_PREEMPTOR}"
    lab.kubectl("delete", "--raw", uri, "-f", "-", payload=json.dumps(delete_options))
    deleted = _fs_wait(lab, lambda s: s[FS_PREEMPTOR]["job"] is None
                       and _fs_workload_by_uid(lab, FS_RECOVERY_TEAMS[1], preemptor_workload_uid) is None,
                       "exact preemptor Job and Workload cleanup")
    preemptor_workload_absent = (_fs_workload_by_uid(
        lab, FS_RECOVERY_TEAMS[1], preemptor_workload_uid) is None)
    recovered = _fs_wait(lab, lambda s: (
        s[FS_VICTIM]["job"] is not None
        and s[FS_VICTIM]["job"].get("metadata", {}).get("uid") == victim_job["metadata"]["uid"]
        and s[FS_VICTIM]["workload"] is not None
        and s[FS_VICTIM]["workload"].get("metadata", {}).get("uid") == victim_workload["metadata"]["uid"]
        and _fs_admitted(s[FS_VICTIM]["workload"], "recovery-team-a-cq")
        and _fs_ready_pod(s[FS_VICTIM]["pods"]) is not None
        and _fs_ready_pod(s[FS_VICTIM]["pods"])["metadata"]["uid"] != victim_pod["metadata"]["uid"]),
        "the same victim Workload to recover with a new Ready Pod", seconds=150)
    new_victim_pod = _fs_ready_pod(recovered[FS_VICTIM]["pods"])
    retain("victim_recovered", preemptor_delete_options=delete_options,
           preemptor_job_uid_absent=deleted[FS_PREEMPTOR]["job"] is None,
           preemptor_workload_uid=preemptor_workload_uid,
           preemptor_workload_uid_absent=preemptor_workload_absent,
           victim_job=recovered[FS_VICTIM]["job"], victim_workload=recovered[FS_VICTIM]["workload"],
           prior_victim_pod_uid=victim_pod["metadata"]["uid"], new_victim_pod=new_victim_pod,
           recovered_pods=recovered[FS_VICTIM]["pods"])
    lab.check("positive", "Removing the exact preemptor restores the same victim Job and Workload with a new Ready Pod",
              recovered[FS_VICTIM]["job"]["metadata"]["uid"] == victim_job["metadata"]["uid"]
              and recovered[FS_VICTIM]["workload"]["metadata"]["uid"] == victim_workload["metadata"]["uid"]
              and new_victim_pod["metadata"]["uid"] != victim_pod["metadata"]["uid"]
              and _fs_ready_pod(recovered[FS_VICTIM]["pods"]) is not None
              and deleted[FS_PREEMPTOR]["job"] is None and preemptor_workload_absent,
              {"same_victim_job_and_workload": True, "preemptor_job_and_workload_absent": True,
               "replacement_ready_pod": True})

    # Keep this helper scoped to its two case-owned namespaces and ClusterQueues.
    for team in FS_RECOVERY_TEAMS:
        lab.kubectl("delete", "namespace", team, "--wait=true", timeout=90)
    for team in FS_RECOVERY_TEAMS:
        lab.kubectl("delete", "clusterqueue", f"{team}-cq", "--wait=true", timeout=60)
    lab.kubectl("delete", "workloadpriorityclasses", baseline_priority, "--wait=true", timeout=45)
    namespaces_absent = all(_fs_json_if_exists(lab, "get", "namespace", team) is None
                            for team in FS_RECOVERY_TEAMS)
    queues_absent = all(_fs_json_if_exists(lab, "get", "clusterqueues", f"{team}-cq") is None
                        for team in FS_RECOVERY_TEAMS)
    priority_absent = _fs_json_if_exists(lab, "get", "workloadpriorityclasses", baseline_priority) is None
    retain("cleanup", namespace_names=FS_RECOVERY_TEAMS, priority_class=baseline_priority,
           namespace_absent=namespaces_absent, clusterqueues_absent=queues_absent,
           priority_class_absent=priority_absent)
    lab.check("positive", "The isolated fair-share recovery namespaces and queues are removed",
              namespaces_absent and queues_absent and priority_absent,
              {"owned_namespaces_removed": namespaces_absent, "owned_clusterqueues_removed": queues_absent,
               "owned_priority_class_absent": priority_absent})


def run(lab):
    # Preserve the published eight checks before the additive recovery witness.
    run_fairshare(lab)
    run_gang_candidate(lab)
    run_cpu_readiness_candidate(lab)
    run_fairshare_preemption_recovery_candidate(lab)
    run_weighted_fairsharing_discriminator(lab)


WFS_COHORT = "weighted-recovery-cohort"
WFS_TEAMS = ("weighted-team-a", "weighted-team-b", "weighted-donor")
WFS_BASELINE = "weighted-baseline"
WFS_VICTIM = "weighted-victim"
WFS_PREEMPTOR = "weighted-preemptor"
WFS_LOW_WEIGHT = "1"
WFS_HIGH_WEIGHT = "10"
WFS_CPU_BASE = "100m"
WFS_CPU_PREEMPTOR = "400m"
WFS_MEMORY = "32Mi"
WFS_BASELINE_PRIORITY = "weighted-baseline-priority"
WFS_PREEMPTOR_PRIORITY = "weighted-preemptor-priority"


def _wfs_condition(workload, kind):
    return next((item for item in (workload or {}).get("status", {}).get("conditions", [])
                 if item.get("type") == kind), None)


def _wfs_ready(pods):
    return next((pod for pod in pods if pod.get("status", {}).get("phase") == "Running"
                 and any(item.get("type") == "Ready" and item.get("status") == "True"
                         for item in pod.get("status", {}).get("conditions", []))), None)


def _wfs_admitted(workload, cq):
    return bool(workload and workload.get("status", {}).get("admission", {}).get("clusterQueue") == cq
                and (_wfs_condition(workload, "Admitted") or {}).get("status") == "True")


def _wfs_job(lab, team, name, cpu, priority_class=None):
    labels = {"kueue.x-k8s.io/queue-name": "work",
              "saf-k8s.example/fixture": "0703-007-weighted-fairsharing"}
    if priority_class:
        labels["kueue.x-k8s.io/priority-class"] = priority_class
    create(lab, {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": team, "labels": labels},
        "spec": {"suspend": True, "parallelism": 1, "completions": 1,
                 "backoffLimit": 0, "activeDeadlineSeconds": 240,
                 "template": {"metadata": {"labels": {"saf-k8s.example/fixture": "0703-007-weighted-fairsharing"}},
                              "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                                       "terminationGracePeriodSeconds": 1,
                                       "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                           "seccompProfile": {"type": "RuntimeDefault"}},
                                       "containers": [{"name": "bounded", "image": BUSYBOX_IMAGE,
                                                       "imagePullPolicy": "IfNotPresent",
                                                       "command": ["sleep", "180"],
                                                       "resources": {"requests": {"cpu": cpu,
                                                                                  "memory": WFS_MEMORY},
                                                                     "limits": {"cpu": cpu,
                                                                                "memory": "64Mi"}},
                                                       "securityContext": {"allowPrivilegeEscalation": False,
                                                                           "readOnlyRootFilesystem": True,
                                                                           "capabilities": {"drop": ["ALL"]}}}]}}},
    })


def _wfs_owned(lab, team, job_obj):
    if not job_obj:
        return None
    uid = job_obj.get("metadata", {}).get("uid")
    records = json.loads(lab.kubectl("get", "workloads", "-n", team, "-o", "json").stdout)["items"]
    owned = [item for item in records if any(
        owner.get("kind") == "Job" and owner.get("apiVersion") == "batch/v1"
        and owner.get("controller") is True and owner.get("uid") == uid
        for owner in item.get("metadata", {}).get("ownerReferences", []))]
    return owned[0] if len(owned) == 1 else None


def _wfs_workload_uid(lab, team, uid):
    records = json.loads(lab.kubectl("get", "workloads", "-n", team, "-o", "json").stdout)["items"]
    return next((item for item in records if item.get("metadata", {}).get("uid") == uid), None)


def _wfs_snapshot(lab):
    out = {}
    for team, name in ((WFS_TEAMS[0], WFS_BASELINE), (WFS_TEAMS[0], WFS_VICTIM),
                       (WFS_TEAMS[1], WFS_PREEMPTOR)):
        job_obj = _fs_json_if_exists(lab, "get", "job", name, "-n", team)
        workload = _wfs_owned(lab, team, job_obj) if job_obj else None
        pods = _fs_owned_pods(lab, team, job_obj) if job_obj else []
        out[name] = {"job": job_obj, "workload": workload, "pods": pods}
    out["clusterqueues"] = {
        "a": objects(lab, "get clusterqueue weighted-team-a-cq"),
        "b": objects(lab, "get clusterqueue weighted-team-b-cq"),
        "donor": objects(lab, "get clusterqueue weighted-donor-cq"),
    }
    return out


def _wfs_wait(lab, predicate, description, seconds=100):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        last = _wfs_snapshot(lab)
        if predicate(last):
            return last
        time.sleep(0.75)
    lab.block(f"Timed out waiting for {description}; last snapshot={last!r}")


def _wfs_borrowed(cq):
    resources = {resource.get("name"): resource
                 for flavor in cq.get("status", {}).get("flavorsReservation", [])
                 for resource in flavor.get("resources", [])}
    return {name: resources.get(name, {}).get("borrowed") for name in ("cpu", "memory")}


def _wfs_quota_shape(clusterqueues):
    out = {}
    for role in ("a", "b", "donor"):
        values = {}
        for group in clusterqueues[role].get("spec", {}).get("resourceGroups", []):
            for flavor in group.get("flavors", []):
                for resource in flavor.get("resources", []):
                    values[resource.get("name")] = resource.get("nominalQuota")
        out[role] = values
    return out


def _wfs_comparison_shape(clusterqueues):
    shape = {}
    for role, obj in clusterqueues.items():
        spec = json.loads(json.dumps(obj.get("spec", {})))
        if role == "b":
            spec.get("fairSharing", {}).pop("weight", None)
        shape[role] = spec
    return shape


def _wfs_request(job_obj):
    spec = job_obj.get("spec", {})
    containers = spec.get("template", {}).get("spec", {}).get("containers", [])
    return {"parallelism": spec.get("parallelism"), "completions": spec.get("completions"),
            "containers": [{"name": container.get("name"),
                            "requests": container.get("resources", {}).get("requests", {})}
                           for container in containers]}


def _wfs_share(cq):
    value = cq.get("status", {}).get("fairSharing", {}).get("weightedShare")
    try:
        share = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return None
    return share if share.is_finite() else None


def run_weighted_fairsharing_discriminator(lab):
    """Change only a bounded peer CQ weight to distinguish fair-share preemption."""
    raw = {"scope": {"cohort": WFS_COHORT, "cpu": {"a_nominal": WFS_CPU_BASE,
             "b_nominal": WFS_CPU_BASE, "donor_nominal": "300m", "preemptor": WFS_CPU_PREEMPTOR},
             "memory_nominal_each": "128Mi", "priority": {"victim": 0, "preemptor": 50,
             "baseline": 100}}, "snapshots": []}

    def retain(step, **values):
        raw["snapshots"].append({"step": step, **values})
        (lab.evidence / "weighted-fairsharing-discriminator-raw.json").write_text(
            json.dumps(raw, indent=2, sort_keys=True) + "\n")

    for team in WFS_TEAMS:
        create(lab, {"apiVersion": "v1", "kind": "Namespace",
                     "metadata": {"name": team,
                                  "labels": {"saf-k8s.example/team": team,
                                             "saf-k8s.example/fixture": "0703-007-weighted-fairsharing"}}})
    quotas = {WFS_TEAMS[0]: WFS_CPU_BASE, WFS_TEAMS[1]: WFS_CPU_BASE, WFS_TEAMS[2]: "300m"}
    for team in WFS_TEAMS:
        queue = team.replace("weighted-", "")
        cq_name = f"{team}-cq"
        create(lab, {"apiVersion": API, "kind": "ClusterQueue", "metadata": {"name": cq_name},
                     "spec": {"namespaceSelector": {"matchLabels": {"saf-k8s.example/team": team}},
                              "cohortName": WFS_COHORT,
                              "resourceGroups": [{"coveredResources": ["cpu", "memory"],
                                  "flavors": [{"name": "virtual-capacity", "resources": [
                                      {"name": "cpu", "nominalQuota": quotas[team]},
                                      {"name": "memory", "nominalQuota": "128Mi" if team != WFS_TEAMS[2] else "256Mi"}]}]}],
                              "preemption": {"reclaimWithinCohort": "Any" if team == WFS_TEAMS[1] else "Never",
                                             "withinClusterQueue": "Never"},
                              "fairSharing": {"weight": WFS_LOW_WEIGHT}}})
        if team != WFS_TEAMS[2]:
            create(lab, {"apiVersion": API, "kind": "LocalQueue",
                         "metadata": {"name": "work", "namespace": team},
                         "spec": {"clusterQueue": cq_name}})
        lab.kubectl("wait", "--for=condition=Active", f"clusterqueue/{cq_name}",
                    "--timeout=60s", timeout=65)
        if team != WFS_TEAMS[2]:
            lab.kubectl("wait", "--for=condition=Active", "localqueue/work", "-n", team,
                        "--timeout=60s", timeout=65)

    create(lab, {"apiVersion": API, "kind": "WorkloadPriorityClass",
                 "metadata": {"name": WFS_BASELINE_PRIORITY}, "value": 100,
                 "description": "Protected bounded baseline for weighted share comparison"})
    create(lab, {"apiVersion": API, "kind": "WorkloadPriorityClass",
                 "metadata": {"name": WFS_PREEMPTOR_PRIORITY}, "value": 50,
                 "description": "Bounded fair-share preemptor above victim, below baseline"})
    _wfs_job(lab, WFS_TEAMS[0], WFS_BASELINE, WFS_CPU_BASE, WFS_BASELINE_PRIORITY)
    baseline = _wfs_wait(lab, lambda s: _wfs_admitted(s[WFS_BASELINE]["workload"], "weighted-team-a-cq")
                         and _wfs_ready(s[WFS_BASELINE]["pods"]), "baseline to become Ready")
    baseline_job = baseline[WFS_BASELINE]["job"]
    baseline_workload = baseline[WFS_BASELINE]["workload"]
    baseline_pod = _wfs_ready(baseline[WFS_BASELINE]["pods"])
    if (baseline_workload.get("spec", {}).get("priority") != 100
            or baseline_workload.get("spec", {}).get("priorityClassRef") != {
                "group": "kueue.x-k8s.io", "kind": "WorkloadPriorityClass",
                "name": WFS_BASELINE_PRIORITY}):
        lab.block("The protected baseline did not record the exact WorkloadPriorityClass reference and value")
    _wfs_job(lab, WFS_TEAMS[0], WFS_VICTIM, WFS_CPU_BASE)
    victim_state = _wfs_wait(lab, lambda s: _wfs_admitted(s[WFS_VICTIM]["workload"], "weighted-team-a-cq")
                             and _wfs_ready(s[WFS_VICTIM]["pods"]), "borrowed victim to become Ready")
    victim_job = victim_state[WFS_VICTIM]["job"]
    victim_workload = victim_state[WFS_VICTIM]["workload"]
    victim_pod = _wfs_ready(victim_state[WFS_VICTIM]["pods"])
    borrowed = _wfs_borrowed(victim_state["clusterqueues"]["a"])
    if borrowed.get("cpu") != WFS_CPU_BASE or borrowed.get("memory") not in (None, "0", "0m", "0Mi"):
        lab.block(f"Team A must borrow exactly 100m CPU and no memory before comparison: {borrowed!r}")
    if (baseline_workload.get("spec", {}).get("priority") != 100
            or victim_workload.get("spec", {}).get("priority", 0) != 0):
        lab.block("The baseline/victim Workload priorities did not match the explicit protection boundary")
    _wfs_job(lab, WFS_TEAMS[1], WFS_PREEMPTOR, WFS_CPU_PREEMPTOR, WFS_PREEMPTOR_PRIORITY)
    low = _wfs_wait(lab, lambda s: (
        s[WFS_PREEMPTOR]["workload"] is not None
        and (_wfs_condition(s[WFS_PREEMPTOR]["workload"], "QuotaReserved") or {}).get("status") == "False"
        and (_wfs_condition(s[WFS_PREEMPTOR]["workload"], "QuotaReserved") or {}).get("reason") == "WaitingForQuota"
        and _wfs_admitted(s[WFS_VICTIM]["workload"], "weighted-team-a-cq")
        and _wfs_ready(s[WFS_VICTIM]["pods"])
        and _wfs_ready(s[WFS_BASELINE]["pods"])),
        "low-weight preemptor to remain pending while the victim and baseline stay Ready")
    donor_quota = low["clusterqueues"]["donor"].get("spec", {}).get("resourceGroups", [])
    low_weight = low["clusterqueues"]["b"].get("spec", {}).get("fairSharing", {}).get("weight")
    low_quota_shape = _wfs_quota_shape(low["clusterqueues"])
    expected_quota_shape = {"a": {"cpu": "100m", "memory": "128Mi"},
                            "b": {"cpu": "100m", "memory": "128Mi"},
                            "donor": {"cpu": "300m", "memory": "256Mi"}}
    if low_weight != WFS_LOW_WEIGHT:
        lab.block(f"The fair-share control did not retain the declared low weight: {low_weight!r}")
    if low_quota_shape != expected_quota_shape:
        lab.block(f"The fair-share quota inputs differed from the exact declared shape: {low_quota_shape!r}")
    low_requests = _wfs_request(low[WFS_PREEMPTOR]["job"])
    expected_requests = {"parallelism": 1, "completions": 1,
                         "containers": [{"name": "bounded", "requests": {"cpu": "400m", "memory": WFS_MEMORY}}]}
    if low_requests != expected_requests:
        lab.block(f"The low-weight preemptor request differed from the exact bounded workload: {low_requests!r}")
    preemptor_job_uid = low[WFS_PREEMPTOR]["job"]["metadata"]["uid"]
    preemptor_workload_uid = low[WFS_PREEMPTOR]["workload"]["metadata"]["uid"]
    if (low[WFS_PREEMPTOR]["workload"].get("spec", {}).get("priority") != 50
            or low[WFS_PREEMPTOR]["workload"].get("spec", {}).get("priorityClassRef") != {
                "group": "kueue.x-k8s.io", "kind": "WorkloadPriorityClass",
                "name": WFS_PREEMPTOR_PRIORITY}):
        lab.block("The exact pending preemptor did not record its structured priority value and class")
    retain("low_weight_pending", baseline_job=baseline_job, baseline_workload=baseline_workload,
           baseline_pod=baseline_pod, victim_job=victim_job, victim_workload=victim_workload,
           victim_ready_pod=victim_pod, preemptor_job=low[WFS_PREEMPTOR]["job"],
           preemptor_workload=low[WFS_PREEMPTOR]["workload"],
           clusterqueues=low["clusterqueues"], borrowed_resources=borrowed,
           preemptor_request=low_requests,
           team_a_weighted_share_before=str(_wfs_share(low["clusterqueues"]["a"])))
    lab.check("red", "At unchanged quota, the low-weight peer remains pending and cannot preempt the borrowed victim",
              low_weight == WFS_LOW_WEIGHT
              and low_quota_shape == expected_quota_shape
              and low[WFS_BASELINE]["job"]["metadata"]["uid"] == baseline_job["metadata"]["uid"]
              and low[WFS_BASELINE]["workload"]["metadata"]["uid"] == baseline_workload["metadata"]["uid"]
              and _wfs_admitted(low[WFS_VICTIM]["workload"], "weighted-team-a-cq")
              and low[WFS_VICTIM]["job"]["metadata"]["uid"] == victim_job["metadata"]["uid"]
              and low[WFS_VICTIM]["workload"]["metadata"]["uid"] == victim_workload["metadata"]["uid"]
              and _wfs_ready(low[WFS_VICTIM]["pods"]) is not None
              and _wfs_ready(low[WFS_VICTIM]["pods"])["metadata"]["uid"] == victim_pod["metadata"]["uid"]
              and _wfs_ready(low[WFS_BASELINE]["pods"])["metadata"]["uid"] == baseline_pod["metadata"]["uid"]
              and low[WFS_PREEMPTOR]["job"]["metadata"]["uid"] == preemptor_job_uid,
              {"low_weight_pending": True, "victim_unchanged": True, "baseline_unchanged": True,
               "team_a_borrowed_100m_cpu": True, "declared_quota_retained": low_quota_shape == expected_quota_shape,
               "donor_nominal_cpu_300m": bool(donor_quota)})

    lab.kubectl("patch", "clusterqueue", "weighted-team-b-cq", "--type=merge", "-p",
                json.dumps({"spec": {"fairSharing": {"weight": WFS_HIGH_WEIGHT}}}))
    fair = _wfs_wait(lab, lambda s: (
        s[WFS_VICTIM]["workload"] is not None
        and (_wfs_condition(s[WFS_VICTIM]["workload"], "Evicted") or {}).get("status") == "True"
        and (_wfs_condition(s[WFS_VICTIM]["workload"], "Evicted") or {}).get("reason") == "Preempted"
        and (_wfs_condition(s[WFS_VICTIM]["workload"], "Preempted") or {}).get("status") == "True"
        and (_wfs_condition(s[WFS_VICTIM]["workload"], "Preempted") or {}).get("reason") == "InCohortFairSharing"
        and not s[WFS_VICTIM]["pods"]
        and s[WFS_PREEMPTOR]["job"] is not None
        and s[WFS_PREEMPTOR]["workload"] is not None
        and _wfs_admitted(s[WFS_PREEMPTOR]["workload"], "weighted-team-b-cq")
        and _wfs_ready(s[WFS_PREEMPTOR]["pods"])
        and _wfs_ready(s[WFS_BASELINE]["pods"])
        and _wfs_ready(s[WFS_BASELINE]["pods"])["metadata"]["uid"] == baseline_pod["metadata"]["uid"]),
        "high-weight exact fair-sharing preemption", seconds=120)
    fw = _wfs_condition(fair[WFS_VICTIM]["workload"], "Preempted")
    slots = re.search(r"\(UID: ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}), "
                      r"JobUID: ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\)",
                      (fw or {}).get("message", ""))
    same_preemptor = bool(slots and slots.group(1) == preemptor_workload_uid
                          and slots.group(2) == preemptor_job_uid)
    hq = fair["clusterqueues"]["b"]
    high_weight = hq.get("spec", {}).get("fairSharing", {}).get("weight")
    high_quota_shape = _wfs_quota_shape(fair["clusterqueues"])
    same_policy_except_weight = (_wfs_comparison_shape(fair["clusterqueues"])
                                 == _wfs_comparison_shape(low["clusterqueues"]))
    high_borrowed = _wfs_borrowed(hq)
    team_a_share_before = _wfs_share(low["clusterqueues"]["a"])
    team_b_share_after = _wfs_share(hq)
    weighted_share_reduced = (team_a_share_before is not None and team_b_share_after is not None
                               and team_a_share_before > 0 and team_b_share_after > 0
                               and team_b_share_after < team_a_share_before)
    retain("high_weight_fairshare_preemption", baseline_job=fair[WFS_BASELINE]["job"],
           baseline_workload=fair[WFS_BASELINE]["workload"], baseline_pod=_wfs_ready(fair[WFS_BASELINE]["pods"]),
           victim_job=fair[WFS_VICTIM]["job"], victim_workload=fair[WFS_VICTIM]["workload"],
           victim_preempted_condition=fw, preemptor_job=fair[WFS_PREEMPTOR]["job"],
           preemptor_workload=fair[WFS_PREEMPTOR]["workload"], preemptor_uid_slots=slots.groups() if slots else None,
           exact_preemptor_identity=same_preemptor, clusterqueues=fair["clusterqueues"],
           team_a_borrowed_before=borrowed,
           team_a_weighted_share_before=str(team_a_share_before) if team_a_share_before is not None else None,
           team_b_weighted_share_after=str(team_b_share_after) if team_b_share_after is not None else None,
           preemptor_borrowed_after=high_borrowed,
           preemptor_request_after=_wfs_request(fair[WFS_PREEMPTOR]["job"]))
    lab.check("green", "Raising only peer fair-share weight admits it through exact InCohortFairSharing preemption",
              high_weight == WFS_HIGH_WEIGHT
              and high_quota_shape == low_quota_shape == expected_quota_shape
              and fair[WFS_VICTIM]["job"]["metadata"]["uid"] == victim_job["metadata"]["uid"]
              and fair[WFS_VICTIM]["workload"]["metadata"]["uid"] == victim_workload["metadata"]["uid"]
              and (_wfs_condition(fair[WFS_VICTIM]["workload"], "Evicted") or {}).get("reason") == "Preempted"
              and (_wfs_condition(fair[WFS_VICTIM]["workload"], "Preempted") or {}).get("reason") == "InCohortFairSharing"
              and fair[WFS_PREEMPTOR]["job"]["metadata"]["uid"] == preemptor_job_uid
              and fair[WFS_PREEMPTOR]["workload"]["metadata"]["uid"] == preemptor_workload_uid
              and _wfs_request(fair[WFS_PREEMPTOR]["job"]) == low_requests
              and same_preemptor
              and _wfs_ready(fair[WFS_PREEMPTOR]["pods"]) is not None
              and fair[WFS_BASELINE]["job"]["metadata"]["uid"] == baseline_job["metadata"]["uid"]
              and fair[WFS_BASELINE]["workload"]["metadata"]["uid"] == baseline_workload["metadata"]["uid"]
              and _wfs_ready(fair[WFS_BASELINE]["pods"])["metadata"]["uid"] == baseline_pod["metadata"]["uid"]
              and same_policy_except_weight and high_borrowed.get("cpu") == "300m"
              and high_borrowed.get("memory") in (None, "0", "0m", "0Mi")
              and weighted_share_reduced,
              {"weight_changed_from_1_to_10": high_weight == WFS_HIGH_WEIGHT,
               "quota_inputs_unchanged": high_quota_shape == low_quota_shape == expected_quota_shape,
               "same_cq_policy_except_weight": same_policy_except_weight,
               "preemptor_borrows_300m_cpu": high_borrowed.get("cpu") == "300m",
               "preemptor_weighted_share_recorded": team_b_share_after is not None,
               "victim_weighted_share_before_recorded": team_a_share_before is not None,
               "preemptor_weighted_share_below_victim_before": weighted_share_reduced,
               "preemptor_memory_within_nominal": high_borrowed.get("memory") in (None, "0", "0m", "0Mi"),
               "exact_fairsharing_reason": True,
               "victim_and_preemptor_uids_match": same_preemptor,
               "baseline_pod_identity_unchanged": True})

    opts = {"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Foreground",
            "preconditions": {"uid": preemptor_job_uid}}
    uri = f"/apis/batch/v1/namespaces/{WFS_TEAMS[1]}/jobs/{WFS_PREEMPTOR}"
    lab.kubectl("delete", "--raw", uri, "-f", "-", payload=json.dumps(opts))
    gone = _wfs_wait(lab, lambda s: s[WFS_PREEMPTOR]["job"] is None
                     and _wfs_workload_uid(lab, WFS_TEAMS[1], preemptor_workload_uid) is None,
                     "the exact weighted preemptor to be removed")
    recovered = _wfs_wait(lab, lambda s: (
        s[WFS_VICTIM]["job"] is not None
        and s[WFS_VICTIM]["job"].get("metadata", {}).get("uid") == victim_job["metadata"]["uid"]
        and s[WFS_VICTIM]["workload"] is not None
        and s[WFS_VICTIM]["workload"].get("metadata", {}).get("uid") == victim_workload["metadata"]["uid"]
        and _wfs_admitted(s[WFS_VICTIM]["workload"], "weighted-team-a-cq")
        and _wfs_ready(s[WFS_VICTIM]["pods"]) is not None
        and _wfs_ready(s[WFS_VICTIM]["pods"])["metadata"]["uid"] != victim_pod["metadata"]["uid"]),
        "same borrowed victim Workload to recover with a new Ready Pod", seconds=150)
    new_pod = _wfs_ready(recovered[WFS_VICTIM]["pods"])
    retain("recovered", preemptor_uid_deleted=gone[WFS_PREEMPTOR]["job"] is None,
           preemptor_workload_uid_deleted=_wfs_workload_uid(lab, WFS_TEAMS[1], preemptor_workload_uid) is None,
           victim_job=recovered[WFS_VICTIM]["job"], victim_workload=recovered[WFS_VICTIM]["workload"],
           old_pod_uid=victim_pod["metadata"]["uid"], new_pod=new_pod)
    lab.check("positive", "Deleting the UID-pinned fair-share preemptor restores the same victim with a new Ready Pod",
              gone[WFS_PREEMPTOR]["job"] is None
              and _wfs_workload_uid(lab, WFS_TEAMS[1], preemptor_workload_uid) is None
              and recovered[WFS_VICTIM]["job"]["metadata"]["uid"] == victim_job["metadata"]["uid"]
              and recovered[WFS_VICTIM]["workload"]["metadata"]["uid"] == victim_workload["metadata"]["uid"]
              and new_pod["metadata"]["uid"] != victim_pod["metadata"]["uid"]
              and _wfs_ready(recovered[WFS_VICTIM]["pods"]) is not None,
              {"preemptor_uids_absent": True, "same_victim_identity_recovered": True,
               "replacement_pod_ready": True})

    for team in WFS_TEAMS:
        lab.kubectl("delete", "namespace", team, "--wait=true", timeout=90)
    for team in WFS_TEAMS:
        lab.kubectl("delete", "clusterqueue", f"{team}-cq", "--wait=true", timeout=60)
    for name in (WFS_BASELINE_PRIORITY, WFS_PREEMPTOR_PRIORITY):
        lab.kubectl("delete", "workloadpriorityclass", name, "--wait=true", timeout=45)
    namespaces_absent = all(_fs_json_if_exists(lab, "get", "namespace", team) is None for team in WFS_TEAMS)
    queues_absent = all(_fs_json_if_exists(lab, "get", "clusterqueue", f"{team}-cq") is None for team in WFS_TEAMS)
    priorities_absent = all(_fs_json_if_exists(lab, "get", "workloadpriorityclass", name) is None
                            for name in (WFS_BASELINE_PRIORITY, WFS_PREEMPTOR_PRIORITY))
    retain("cleanup", namespaces_absent=namespaces_absent, clusterqueues_absent=queues_absent,
           priority_classes_absent=priorities_absent)
    lab.check("positive", "The weighted fair-share cohort, namespaces and priority classes are removed",
              namespaces_absent and queues_absent and priorities_absent,
              {"owned_namespaces_removed": namespaces_absent,
               "owned_clusterqueues_removed": queues_absent, "priority_classes_removed": priorities_absent})
