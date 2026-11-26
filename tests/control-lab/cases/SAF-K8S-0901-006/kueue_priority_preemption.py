"""Bounded Kueue v0.17.7 same-ClusterQueue preemption and recovery witness."""
import json
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
QUEUE = runpy.run_path(str(HERE / "queue_admission.py"))
AFS = runpy.run_path(str(HERE / "admission_fair_sharing.py"))

SUFFIX = "0901-006-kqpreempt"
NAMESPACE = f"saf-{SUFFIX}"
CQ = f"saf-cq-{SUFFIX}"
LQ = f"saf-lq-{SUFFIX}"
FLAVOR = f"saf-flavor-{SUFFIX}"
LOW_CLASS = f"saf-{SUFFIX}-low"
HIGH_CLASS = f"saf-{SUFFIX}-high"
LOW_JOB = f"saf-{SUFFIX}-victim"
HIGH_JOB = f"saf-{SUFFIX}-preemptor"
MATCH = "saf-k8s.io/0901-006-kueue-preemption"
PRIORITY_LABEL = "kueue.x-k8s.io/priority-class"
LOW_VALUE = 10
HIGH_VALUE = 100
CPU = "100m"


def _condition(workload, kind):
    return QUEUE["_condition"](workload, kind)


def _own_pods(api, lab, job):
    namespace = job["metadata"]["namespace"]
    uid = job["metadata"]["uid"]
    pods = api["_json"](lab, "get", "pods", "-n", namespace).get("items", [])
    return [pod for pod in pods if any(
        owner.get("kind") == "Job" and owner.get("uid") == uid
        and owner.get("controller") is True
        for owner in pod.get("metadata", {}).get("ownerReferences", []))]


def _wait_workload(api, lab, job, predicate, description, seconds=60):
    def observed():
        current_job = api["_json"](lab, "get", "job", job["metadata"]["name"],
                                    "-n", job["metadata"]["namespace"])
        workload = QUEUE["_owned_workload"](lab, job["metadata"]["namespace"], current_job)
        if workload is None or current_job["metadata"].get("uid") != job["metadata"].get("uid"):
            return None
        if predicate(workload, current_job):
            return {"job": current_job, "workload": workload}
        return None

    return api["_wait"](lab, observed, description, seconds=seconds)


def _make_job(namespace, name, priority_class):
    job = QUEUE["_job"](namespace, name, QUEUE["DEFAULT_JOB_IMAGE"], CPU)
    job["metadata"]["labels"]["kueue.x-k8s.io/queue-name"] = LQ
    job["metadata"]["labels"][PRIORITY_LABEL] = priority_class
    job["spec"]["parallelism"] = 1
    job["spec"]["completions"] = 1
    job["spec"]["activeDeadlineSeconds"] = 720
    container = job["spec"]["template"]["spec"]["containers"][0]
    container["command"] = ["/bin/sh", "-c", "sleep 600; printf '%s\\n' kueue-preemption-fixture"]
    container["resources"] = {"requests": {"cpu": CPU}}
    job["spec"]["template"]["spec"].pop("priorityClassName", None)
    return job


def _wait_ready_pod(api, lab, job, seconds=75):
    return AFS["_wait_job_pod_ready"](
        api, lab, job["metadata"]["namespace"], job["metadata"]["name"], seconds=seconds)


def _priority_matches(workload, name, value):
    return (workload.get("spec", {}).get("priorityClassRef") == {
        "group": "kueue.x-k8s.io", "kind": "WorkloadPriorityClass", "name": name,
    } and workload.get("spec", {}).get("priority") == value)


def _exact_cpu_reservation(workload):
    admission = workload.get("status", {}).get("admission") or {}
    assignments = admission.get("podSetAssignments", [])
    return (admission.get("clusterQueue") == CQ and len(assignments) == 1
            and assignments[0].get("count") == 1
            and assignments[0].get("flavors", {}).get("cpu") == FLAVOR
            and str(assignments[0].get("resourceUsage", {}).get("cpu")) == CPU)


def run(lab):
    api = AFS["_api"]()
    api["_apply"](lab, {"apiVersion": "v1", "kind": "Namespace",
                        "metadata": {"name": NAMESPACE, "labels": {MATCH: SUFFIX}}})
    api["_apply"](lab, {"apiVersion": "kueue.x-k8s.io/v1beta2", "kind": "ResourceFlavor",
                        "metadata": {"name": FLAVOR}, "spec": {}})
    api["_apply"](lab, {
        "apiVersion": "kueue.x-k8s.io/v1beta2", "kind": "ClusterQueue",
        "metadata": {"name": CQ},
        "spec": {
            "namespaceSelector": {"matchLabels": {MATCH: SUFFIX}},
            "queueingStrategy": "StrictFIFO",
            "admissionScope": {"admissionMode": "NoAdmissionFairSharing"},
            "preemption": {"withinClusterQueue": "LowerPriority"},
            "resourceGroups": [{"coveredResources": ["cpu"], "flavors": [{
                "name": FLAVOR,
                "resources": [{"name": "cpu", "nominalQuota": CPU}],
            }]}],
        },
    })
    api["_apply"](lab, {"apiVersion": "kueue.x-k8s.io/v1beta2", "kind": "LocalQueue",
                        "metadata": {"name": LQ, "namespace": NAMESPACE},
                        "spec": {"clusterQueue": CQ}})
    for name, value in ((LOW_CLASS, LOW_VALUE), (HIGH_CLASS, HIGH_VALUE)):
        api["_apply"](lab, {"apiVersion": "kueue.x-k8s.io/v1beta2", "kind": "WorkloadPriorityClass",
                            "metadata": {"name": name}, "value": value,
                            "description": "Fixed inert Kueue preemption fixture"})

    cluster_queue = api["_wait"](lab, lambda: (
        obj if (obj := api["_json"](lab, "get", "clusterqueue", CQ))
        and any(c.get("type") == "Active" and c.get("status") == "True"
                for c in obj.get("status", {}).get("conditions", [])) else None
    ), "the isolated preemption ClusterQueue to become Active")
    raw = {"cluster_queue": cluster_queue, "nominal_cpu": CPU,
           "low_priority": LOW_VALUE, "high_priority": HIGH_VALUE}

    def persist():
        (lab.evidence / "kueue-within-cluster-queue-preemption-raw.json").write_text(
            json.dumps(raw, sort_keys=True, indent=2) + "\n")

    persist()
    lab.check("positive", "The isolated ClusterQueue enables only lower-priority within-queue preemption",
              cluster_queue.get("spec", {}).get("preemption", {}).get("withinClusterQueue") == "LowerPriority"
              and not cluster_queue.get("spec", {}).get("cohortName")
              and cluster_queue.get("spec", {}).get("admissionScope", {}).get("admissionMode")
              == "NoAdmissionFairSharing",
              {"within_cluster_queue_lower_priority": True,
               "separate_no_cohort_queue": True,
               "admission_fair_sharing_disabled": True})

    low_manifest = _make_job(NAMESPACE, LOW_JOB, LOW_CLASS)
    api["_apply"](lab, low_manifest)
    low = api["_wait"](lab, lambda: (
        obj if (obj := api["_json"](lab, "get", "job", LOW_JOB, "-n", NAMESPACE))
        and obj.get("metadata", {}).get("uid") else None
    ), "the exact low-priority Job UID", seconds=30)
    low_admitted = _wait_workload(
        api, lab, low,
        lambda w, j: _condition(w, "QuotaReserved") is not None
        and _condition(w, "QuotaReserved").get("status") == "True"
        and _exact_cpu_reservation(w)
        and j.get("spec", {}).get("suspend") is False
        and _priority_matches(w, LOW_CLASS, LOW_VALUE),
        "the exact low-priority Workload to be admitted", seconds=50)
    low_ready = _wait_ready_pod(api, lab, low, seconds=75)
    low_pod = low_ready["pod"]
    raw["low_initial"] = {"job": low_admitted["job"], "workload": low_admitted["workload"],
                          "pod": low_pod}
    persist()
    lab.check("positive", "The low-priority fixture Workload reserves the exact queue quota and runs its owned Pod",
              low_admitted["workload"].get("spec", {}).get("queueName") == LQ
              and _priority_matches(low_admitted["workload"], LOW_CLASS, LOW_VALUE)
              and low_pod.get("status", {}).get("phase") == "Running"
              and not low_admitted["job"].get("spec", {}).get("template", {}).get("spec", {}).get("priorityClassName"),
              {"low_workload_priority_observed": True,
               "exact_local_and_cluster_queue": True,
               "one_job_owned_pod_ready": True,
               "pod_priority_class_absent": True})

    high_manifest = _make_job(NAMESPACE, HIGH_JOB, HIGH_CLASS)
    api["_apply"](lab, high_manifest)
    high = api["_wait"](lab, lambda: (
        obj if (obj := api["_json"](lab, "get", "job", HIGH_JOB, "-n", NAMESPACE))
        and obj.get("metadata", {}).get("uid") else None
    ), "the exact high-priority Job UID", seconds=30)
    high_admitted = _wait_workload(
        api, lab, high,
        lambda w, j: _condition(w, "QuotaReserved") is not None
        and _condition(w, "QuotaReserved").get("status") == "True"
        and _condition(w, "Admitted") is not None
        and _condition(w, "Admitted").get("status") == "True"
        and _exact_cpu_reservation(w)
        and j.get("spec", {}).get("suspend") is False
        and _priority_matches(w, HIGH_CLASS, HIGH_VALUE),
        "the high-priority Workload to replace the lower-priority reservation", seconds=75)
    high_ready = _wait_ready_pod(api, lab, high, seconds=75)
    high_uid = high_admitted["job"]["metadata"]["uid"]
    high_workload_uid = high_admitted["workload"]["metadata"]["uid"]
    preempting_identity = f"(UID: {high_workload_uid}, JobUID: {high_uid})"

    def low_preempted():
        current_job = api["_json"](lab, "get", "job", LOW_JOB, "-n", NAMESPACE)
        workload = QUEUE["_owned_workload"](lab, NAMESPACE, current_job)
        if workload is None:
            return None
        evicted = _condition(workload, "Evicted")
        preempted = _condition(workload, "Preempted")
        if (current_job.get("metadata", {}).get("uid") == low["metadata"]["uid"]
                and workload.get("metadata", {}).get("uid")
                == low_admitted["workload"]["metadata"]["uid"]
                and evicted and evicted.get("status") == "True" and evicted.get("reason") == "Preempted"
                and preempted and preempted.get("status") == "True"
                and preempted.get("reason") == "InClusterQueue"
                and preempting_identity in preempted.get("message", "")
                and current_job.get("spec", {}).get("suspend") is True
                and not _own_pods(api, lab, current_job)):
            return {"job": current_job, "workload": workload}
        return None

    low_evicted = api["_wait"](lab, low_preempted,
                                "the exact low-priority Workload eviction and Job suspension", seconds=40)
    high_owned_pod = high_ready["pod"]
    preempted = _condition(low_evicted["workload"], "Preempted")
    raw["preemption"] = {"evicted_victim": low_evicted, "preemptor": high_admitted,
                          "preemptor_ready_pod": high_owned_pod, "preempted_condition": preempted}
    persist()
    lab.check("green", "Kueue preempts only the lower-priority fixture Workload and runs the exact higher-priority Job",
              _priority_matches(high_admitted["workload"], HIGH_CLASS, HIGH_VALUE)
              and _condition(low_evicted["workload"], "Evicted").get("reason") == "Preempted"
              and preempted.get("reason") == "InClusterQueue"
              and preempting_identity in preempted.get("message", "")
              and high_owned_pod.get("status", {}).get("phase") == "Running",
              {"high_workload_priority_observed": True,
               "low_workload_evicted_as_preempted": True,
               "within_queue_condition_identifies_exact_preemptor": True,
               "victim_job_suspended": True,
               "victim_owned_pods_removed": True,
               "preemptor_owned_pod_ready": True})

    old_low_pod_uid = low_pod.get("metadata", {}).get("uid")
    live_preemptor = api["_json"](lab, "get", "job", HIGH_JOB, "-n", NAMESPACE)
    if live_preemptor.get("metadata", {}).get("uid") != high_uid:
        lab.block("The preemptor Job UID changed before its cleanup")
    preemptor_workload = QUEUE["_owned_workload"](lab, NAMESPACE, live_preemptor)
    if preemptor_workload is None:
        lab.block("The exact preemptor Workload disappeared before cleanup evidence was captured")
    preemptor_workload_uid = preemptor_workload.get("metadata", {}).get("uid")
    if preemptor_workload_uid != high_admitted["workload"].get("metadata", {}).get("uid"):
        lab.block("The preemptor Workload UID changed before its cleanup")
    if not any(owner.get("kind") == "Job" and owner.get("uid") == high_uid
               for owner in preemptor_workload.get("metadata", {}).get("ownerReferences", [])):
        lab.block("The preemptor Workload does not reference the exact Job UID")
    preemptor_cleanup_evidence = {
        "job_uid": high_uid,
        "workload_uid": preemptor_workload_uid,
        "workload_conditions": preemptor_workload.get("status", {}).get("conditions", []),
        "admission": preemptor_workload.get("status", {}).get("admission"),
        "requeue_state": preemptor_workload.get("status", {}).get("requeueState"),
    }
    api["_kubectl"](lab, "delete", "job", HIGH_JOB, "-n", NAMESPACE,
                    "--cascade=foreground", "--wait=true", "--timeout=35s", timeout=40)

    def preemptor_retired():
        jobs = api["_json"](lab, "get", "jobs", "-n", NAMESPACE).get("items", [])
        workloads = api["_json"](lab, "get", "workloads.kueue.x-k8s.io", "-n", NAMESPACE).get("items", [])
        pods = api["_json"](lab, "get", "pods", "-n", NAMESPACE).get("items", [])
        job_absent = not any(item.get("metadata", {}).get("uid") == high_uid for item in jobs)
        workload_absent = not any(item.get("metadata", {}).get("uid") == preemptor_workload_uid
                                  for item in workloads)
        owned_pods_absent = not any(
            any(owner.get("kind") == "Job" and owner.get("uid") == high_uid
                and owner.get("controller") is True
                for owner in pod.get("metadata", {}).get("ownerReferences", []))
            for pod in pods
        )
        return {"job_uid_absent": job_absent, "workload_uid_absent": workload_absent,
                "owned_pods_absent": owned_pods_absent} if (
                    job_absent and workload_absent and owned_pods_absent) else None

    preemptor_cleanup = api["_wait"](
        lab, preemptor_retired,
        "the exact preemptor Job, Workload, and owned Pod to be removed", seconds=40)
    raw["preemptor_cleanup"] = {**preemptor_cleanup_evidence, **preemptor_cleanup}
    persist()
    lab.check("positive", "Foreground deletion removes the exact preemptor Job, Workload and owned Pod",
              preemptor_cleanup["job_uid_absent"] and preemptor_cleanup["workload_uid_absent"]
              and preemptor_cleanup["owned_pods_absent"],
              {"preemptor_job_uid_absent": preemptor_cleanup["job_uid_absent"],
               "preemptor_workload_uid_absent": preemptor_cleanup["workload_uid_absent"],
               "preemptor_owned_pods_absent": preemptor_cleanup["owned_pods_absent"]})

    recovered = _wait_workload(
        api, lab, low,
        lambda w, j: _condition(w, "QuotaReserved") is not None
        and _condition(w, "QuotaReserved").get("status") == "True"
        and _condition(w, "Admitted") is not None
        and _condition(w, "Admitted").get("status") == "True"
        and _exact_cpu_reservation(w)
        and j.get("spec", {}).get("suspend") is False
        and _priority_matches(w, LOW_CLASS, LOW_VALUE),
        "the original low-priority Job to recover its quota reservation", seconds=75)
    low_recovered_ready = _wait_ready_pod(api, lab, low, seconds=75)
    new_low_pod = low_recovered_ready["pod"]
    recovered_ok = (
        recovered["job"].get("metadata", {}).get("uid") == low["metadata"].get("uid")
        and bool(old_low_pod_uid)
        and bool(new_low_pod.get("metadata", {}).get("uid"))
        and new_low_pod.get("metadata", {}).get("uid") != old_low_pod_uid
        and recovered["workload"].get("status", {}).get("admission", {}).get("clusterQueue") == CQ
        and _priority_matches(recovered["workload"], LOW_CLASS, LOW_VALUE)
        and high_uid != recovered["job"].get("metadata", {}).get("uid")
    )
    raw["recovery"] = {"deleted_preemptor_uid": high_uid, "recovered_low": recovered,
                        "original_low_pod_uid": old_low_pod_uid, "replacement_low_pod": new_low_pod}
    persist()
    lab.check("positive", "Releasing the preemptor's quota restores the same low Job with a new Ready Pod",
              recovered_ok,
              {"original_job_uid_retained": True,
               "new_pod_uid_after_recovery": True,
               "low_workload_priority_preserved": True,
               "queue_quota_recovered": True})
    raw["retired_recovered_victim"] = AFS["_retire_owned_job"](
        api, lab, NAMESPACE, LOW_JOB, recovered["workload"])
    persist()
