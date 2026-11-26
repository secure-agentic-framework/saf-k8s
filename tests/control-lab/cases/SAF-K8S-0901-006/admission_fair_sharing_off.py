"""Bounded StrictFIFO comparator with Kueue Admission Fair Sharing disabled."""
import json
import runpy
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
AFS = runpy.run_path(str(HERE / "admission_fair_sharing.py"))
SUFFIX = "0901-006-fifo-control"
N_HIGH = f"saf-{SUFFIX}-high"
N_LOW = f"saf-{SUFFIX}-low"
N_HOLDER = f"saf-{SUFFIX}-holder"
CQ = f"saf-cq-{SUFFIX}"
FLAVOR = f"saf-flavor-{SUFFIX}"
LQ_HIGH = f"saf-lq-{SUFFIX}-high"
LQ_LOW = f"saf-lq-{SUFFIX}-low"
LQ_HOLDER = f"saf-lq-{SUFFIX}-holder"
SEED = f"saf-{SUFFIX}-seed"
HOLDER = f"saf-{SUFFIX}-holder-job"
HIGH = f"saf-{SUFFIX}-older-high"
LOW = f"saf-{SUFFIX}-newer-low"
MATCH = "saf-k8s.io/admission-fair-sharing-control"


def _queue_snapshot(api, lab, namespace, queue):
    """Keep exact mode-off accounting and quota use in raw evidence."""
    obj = api["_json"](lab, "get", "localqueue", queue, "-n", namespace)
    status = obj.get("status", {})
    fair = status.get("fairSharing", {})
    return {
        "metadata": {"name": obj.get("metadata", {}).get("name"),
                     "namespace": obj.get("metadata", {}).get("namespace"),
                     "uid": obj.get("metadata", {}).get("uid"),
                     "resourceVersion": obj.get("metadata", {}).get("resourceVersion")},
        "spec": obj.get("spec", {}),
        "admissionFairSharingStatus": fair.get("admissionFairSharingStatus", {}),
        "flavorsReservation": status.get("flavorsReservation", []),
        "flavorsUsage": status.get("flavorsUsage", []),
        "admittedWorkloads": status.get("admittedWorkloads"),
        "reservingWorkloads": status.get("reservingWorkloads"),
        "pendingWorkloads": status.get("pendingWorkloads"),
    }


def _flavor_cpu_total(snapshot, field):
    return [(flavor.get("name"), str(resource.get("total", "0")))
            for flavor in snapshot.get(field, [])
            for resource in flavor.get("resources", [])
            if resource.get("name") == "cpu"]


def _workload_resource_signature(workload):
    """Compare the fixed image and CPU resources, excluding sleep duration."""
    return [{
        "name": pod_set.get("name"),
        "count": pod_set.get("count"),
        "containers": [{
            "name": container.get("name"),
            "image": container.get("image"),
            "requests": container.get("resources", {}).get("requests", {}),
            "limits": container.get("resources", {}).get("limits", {}),
        } for container in pod_set.get("template", {}).get("spec", {}).get("containers", [])],
    } for pod_set in workload.get("spec", {}).get("podSets", [])]


def _wait_pending(api, lab, namespace, job, seconds=45):
    name = job["metadata"]["name"]

    def observed():
        live_job = api["_json"](lab, "get", "job", name, "-n", namespace)
        if live_job.get("spec", {}).get("suspend") is not True:
            return None
        workload = api["_owned_workload"](lab, namespace, live_job)
        if workload is None:
            return None
        job_uid = live_job["metadata"]["uid"]
        if not any(owner.get("kind") == "Job" and owner.get("uid") == job_uid
                   for owner in workload["metadata"].get("ownerReferences", [])):
            return None
        status = workload.get("status", {})
        reservation = api["_condition"](workload, "QuotaReserved") or {}
        admission = api["_condition"](workload, "Admitted") or {}
        if (status.get("admission") is None and reservation.get("status") != "True"
                and admission.get("status") != "True"):
            return workload
        return None

    return api["_wait"](lab, observed, f"owned suspended Job {name} without a reservation", seconds=seconds)


def run(lab):
    # Use the same adapter factory as the AFS case; helper callables stay bound
    # to the queue-admission module namespace in this independent comparator.
    api = AFS["_api"]()
    raw = {"mode": "NoAdmissionFairSharing", "queueing_strategy": "StrictFIFO"}

    def persist():
        (lab.evidence / "kueue-admission-fair-sharing-off-raw.json").write_text(
            json.dumps(raw, sort_keys=True, indent=2) + "\n")

    for namespace in (N_HIGH, N_LOW, N_HOLDER):
        api["_apply"](lab, {"apiVersion": "v1", "kind": "Namespace",
                            "metadata": {"name": namespace,
                                         "labels": {MATCH: SUFFIX}}})
    api["_apply"](lab, {"apiVersion": "kueue.x-k8s.io/v1beta2", "kind": "ResourceFlavor",
                        "metadata": {"name": FLAVOR}, "spec": {}})
    api["_apply"](lab, {
        "apiVersion": "kueue.x-k8s.io/v1beta2", "kind": "ClusterQueue",
        "metadata": {"name": CQ},
        "spec": {
            "namespaceSelector": {"matchLabels": {MATCH: SUFFIX}},
            "queueingStrategy": "StrictFIFO",
            "admissionScope": {"admissionMode": "NoAdmissionFairSharing"},
            "resourceGroups": [{"coveredResources": ["cpu"], "flavors": [{
                "name": FLAVOR,
                "resources": [{"name": "cpu", "nominalQuota": "100m"}],
            }]}],
        },
    })
    for namespace, queue in ((N_HIGH, LQ_HIGH), (N_LOW, LQ_LOW), (N_HOLDER, LQ_HOLDER)):
        api["_apply"](lab, {"apiVersion": "kueue.x-k8s.io/v1beta2", "kind": "LocalQueue",
                            "metadata": {"name": queue, "namespace": namespace},
                            "spec": {"clusterQueue": CQ}})
    cluster_queue = api["_wait"](lab, lambda: (
        obj if (obj := api["_json"](lab, "get", "clusterqueue", CQ))
        and any(c.get("type") == "Active" and c.get("status") == "True"
                for c in obj.get("status", {}).get("conditions", [])) else None
    ), "the independent no-AFS FIFO ClusterQueue to become Active")
    raw["cluster_queue"] = cluster_queue
    persist()
    lab.check("positive", "The comparator uses a separate StrictFIFO ClusterQueue with AFS explicitly disabled",
              cluster_queue.get("spec", {}).get("admissionScope", {}).get("admissionMode")
              == "NoAdmissionFairSharing",
              {"separate_cluster_queue": True,
               "strict_fifo": True,
               "admission_fair_sharing_disabled": True})

    seed = AFS["_fixture_job"](api, N_HIGH, SEED, LQ_HIGH, seconds=20)
    api["_apply"](lab, seed)
    seed_workload = AFS["_wait_workload"](api, lab, N_HIGH, seed, quota_reserved=True)
    seed_ready = AFS["_wait_job_pod_ready"](api, lab, N_HIGH, SEED)
    seed_job = seed_ready["job"]
    seed_pod = seed_ready["pod"]
    seed_assignment = seed_workload.get("status", {}).get("admission", {})
    assignments = seed_assignment.get("podSetAssignments", [])
    assignment_exact = (
        seed_assignment.get("clusterQueue") == CQ
        and seed_workload.get("spec", {}).get("queueName") == LQ_HIGH
        and len(assignments) == 1
        and assignments[0].get("name") == "main"
        and assignments[0].get("count") == 1
        and assignments[0].get("flavors", {}).get("cpu") == FLAVOR
        and str(assignments[0].get("resourceUsage", {}).get("cpu")) == "100m"
    )
    exact_seed_request = (
        seed["spec"]["template"]["spec"]["containers"][0]
        .get("resources", {}).get("requests", {}).get("cpu") == "100m"
    )
    if not assignment_exact or not exact_seed_request:
        lab.block("The mode-off seed did not reserve the exact 100m CPU fixture assignment")

    initial_snapshot = _queue_snapshot(api, lab, N_HIGH, LQ_HIGH)
    initial_update = initial_snapshot.get("admissionFairSharingStatus", {}).get("lastUpdate")
    updated_snapshot = api["_wait"](lab, lambda: (
        snapshot if (snapshot := _queue_snapshot(api, lab, N_HIGH, LQ_HIGH))
        and snapshot.get("admissionFairSharingStatus", {}).get("lastUpdate")
        and snapshot.get("admissionFairSharingStatus", {}).get("lastUpdate") != initial_update
        and _flavor_cpu_total(snapshot, "flavorsReservation") == [(FLAVOR, "100m")]
        and _flavor_cpu_total(snapshot, "flavorsUsage") == [(FLAVOR, "100m")]
        else None
    ), "mode-off LocalQueue update with the exact live 100m reservation", seconds=8)
    low_jobs_before = api["_json"](lab, "get", "jobs", "-n", N_LOW).get("items", [])
    low_workloads_before = api["_json"](lab, "get", "workloads", "-n", N_LOW).get("items", [])
    low_has_no_seed = (
        all(item.get("metadata", {}).get("name") != SEED for item in low_jobs_before)
        and all(not any(owner.get("kind") == "Job" and owner.get("name") == SEED
                        for owner in item.get("metadata", {}).get("ownerReferences", []))
                for item in low_workloads_before)
    )
    seed_complete = api["_wait"](lab, lambda: (
        obj if (obj := api["_json"](lab, "get", "job", SEED, "-n", N_HIGH))
        and any(c.get("type") == "Complete" and c.get("status") == "True"
                for c in obj.get("status", {}).get("conditions", [])) else None
    ), "the comparator's inert usage seed Job to complete independently", seconds=40)
    low_snapshot = _queue_snapshot(api, lab, N_LOW, LQ_LOW)
    high_accounting = updated_snapshot.get("admissionFairSharingStatus", {})
    zero_afs_accounting = str(high_accounting.get("consumedResources", {}).get("cpu", "0")) == "0"
    seed_assignment_ok = (
        assignment_exact and exact_seed_request and low_has_no_seed
        and bool(seed_pod.get("metadata", {}).get("uid"))
        and seed_pod.get("status", {}).get("phase") == "Running"
        and any(c.get("type") == "Ready" and c.get("status") == "True"
                for c in seed_pod.get("status", {}).get("conditions", []))
        and seed_job.get("metadata", {}).get("uid") == seed_complete.get("metadata", {}).get("uid")
        and any(c.get("type") == "Complete" and c.get("status") == "True"
                for c in seed_complete.get("status", {}).get("conditions", []))
        and updated_snapshot.get("admissionFairSharingStatus", {}).get("lastUpdate") != initial_update
    )
    raw["seed_workload"] = seed_workload
    raw["seed_ready_pod"] = seed_ready
    raw["seed_assignment_exact"] = assignment_exact
    raw["seed_queue_before_sample_update"] = initial_snapshot
    raw["seed_queue_after_sample_update"] = updated_snapshot
    raw["seed_completed_job"] = seed_complete
    raw["low_namespace_before_candidates"] = {
        "jobs": low_jobs_before, "workloads": low_workloads_before,
        "queue_snapshot": low_snapshot,
    }
    persist()
    lab.check("positive", "The mode-off 100m seed is admitted and Ready in its exact queue, then completes while the peer remains unseeded",
              seed_assignment_ok,
              {"exact_100m_assignment_observed": assignment_exact,
               "seed_job_owned_pod_ready": seed_assignment_ok,
               "seed_job_completed_after_ready": seed_assignment_ok,
               "peer_queue_received_no_seed": low_has_no_seed,
               "mode_off_last_update_advanced": True,
               "afs_specific_consumed_cpu_zero_observed": zero_afs_accounting})

    raw["retired_seed_before_holder"] = AFS["_retire_owned_job"](
        api, lab, N_HIGH, SEED, seed_workload)

    holder = AFS["_fixture_job"](api, N_HOLDER, HOLDER, LQ_HOLDER, seconds=120)
    api["_apply"](lab, holder)
    holder_workload = AFS["_wait_workload"](api, lab, N_HOLDER, holder, quota_reserved=True)
    holder_pod = AFS["_wait_job_pod_ready"](api, lab, N_HOLDER, HOLDER)
    older = AFS["_fixture_job"](api, N_HIGH, HIGH, LQ_HIGH, seconds=45)
    newer = AFS["_fixture_job"](api, N_LOW, LOW, LQ_LOW, seconds=45)
    api["_apply"](lab, older)
    _wait_pending(api, lab, N_HIGH, older)
    time.sleep(1.2)
    api["_apply"](lab, newer)
    _wait_pending(api, lab, N_LOW, newer)
    # Re-read the exact live Workloads at the selection boundary.
    older_workload = _wait_pending(api, lab, N_HIGH, older, seconds=15)
    newer_workload = _wait_pending(api, lab, N_LOW, newer, seconds=15)
    older_time = AFS["_timestamp"](older_workload.get("metadata", {}).get("creationTimestamp"))
    newer_time = AFS["_timestamp"](newer_workload.get("metadata", {}).get("creationTimestamp"))
    priorities = [seed_workload.get("spec", {}).get("priority", 0),
                  older_workload.get("spec", {}).get("priority", 0),
                  newer_workload.get("spec", {}).get("priority", 0)]
    same_priority = priorities[0] == priorities[1] == priorities[2]
    signatures = {
        "seed": _workload_resource_signature(seed_workload),
        "older_seeded_queue_candidate": _workload_resource_signature(older_workload),
        "newer_unseeded_queue_candidate": _workload_resource_signature(newer_workload),
    }
    same_fixture_inputs = bool(signatures["seed"]
                               and signatures["seed"] == signatures["older_seeded_queue_candidate"]
                               == signatures["newer_unseeded_queue_candidate"])
    ordered = bool(same_priority and older_time and newer_time and older_time < newer_time)
    if not same_priority or not same_fixture_inputs or not ordered:
        lab.block("Live FIFO candidates differ in priority, seed-matched inputs, or creation order")
    raw["holder_workload"] = holder_workload
    raw["holder_ready_pod"] = holder_pod
    raw["older_workload"] = older_workload
    raw["newer_workload"] = newer_workload
    raw["same_priority_values"] = priorities
    raw["same_fixture_input_signatures"] = signatures
    persist()
    lab.check("positive", "Live equal-priority FIFO candidates use the same 100m inputs as the seeded Workload, with the older candidate first",
              ordered and same_fixture_inputs,
              {"equal_live_priorities": same_priority,
               "seeded_and_unseeded_inputs_match": same_fixture_inputs,
               "older_candidate_created_first": True,
               "both_candidates_held": True})

    pre_release_high = _queue_snapshot(api, lab, N_HIGH, LQ_HIGH)
    pre_release_low = _queue_snapshot(api, lab, N_LOW, LQ_LOW)
    pre_release_holder = _queue_snapshot(api, lab, N_HOLDER, LQ_HOLDER)
    holder_reserved = _flavor_cpu_total(pre_release_holder, "flavorsReservation") == [(FLAVOR, "100m")]
    high_pending_unreserved = _flavor_cpu_total(pre_release_high, "flavorsReservation") == [(FLAVOR, "0")]
    low_pending_unreserved = _flavor_cpu_total(pre_release_low, "flavorsReservation") == [(FLAVOR, "0")]
    raw["pre_release_queue_status"] = {
        "high": pre_release_high, "low": pre_release_low, "holder": pre_release_holder,
        "afs_specific_accounting": {
            "high": pre_release_high.get("admissionFairSharingStatus", {}),
            "low": pre_release_low.get("admissionFairSharingStatus", {}),
            "holder": pre_release_holder.get("admissionFairSharingStatus", {}),
        },
    }
    persist()
    lab.check("positive", "Immediately before release, the exact holder owns 100m and both FIFO candidates remain held",
              holder_reserved and high_pending_unreserved and low_pending_unreserved,
              {"holder_holds_nominal_100m": holder_reserved,
               "older_candidate_unreserved": high_pending_unreserved,
               "newer_candidate_unreserved": low_pending_unreserved,
               "mode_off_accounting_retained_in_raw": True})

    api["_kubectl"](lab, "delete", "job", HOLDER, "-n", N_HOLDER, "--wait=true", timeout=45)
    first = AFS["_wait_workload"](api, lab, N_HIGH, older, quota_reserved=True, seconds=40)
    second_held = _wait_pending(api, lab, N_LOW, newer, seconds=15)
    first_job = AFS["_wait_job_suspended"](api, lab, N_HIGH, HIGH, False)
    second_job = AFS["_wait_job_suspended"](api, lab, N_LOW, LOW, True)
    fifo_selected = (first.get("spec", {}).get("queueName") == LQ_HIGH
                     and second_held.get("spec", {}).get("queueName") == LQ_LOW
                     and first_job.get("spec", {}).get("suspend") is False
                     and second_job.get("spec", {}).get("suspend") is True)
    raw["fifo_first"] = {"workload": first, "pending": second_held,
                         "admitted_job": first_job, "pending_job": second_job}
    persist()
    lab.check("green", "With AFS explicitly disabled, StrictFIFO admits the older seed-matched candidate first",
              fifo_selected,
              {"older_high_use_first": fifo_selected,
               "newer_low_use_still_pending": fifo_selected})

    api["_kubectl"](lab, "delete", "job", HIGH, "-n", N_HIGH, "--wait=true", timeout=45)
    final = AFS["_wait_workload"](api, lab, N_LOW, newer, quota_reserved=True, seconds=40)
    final_job = AFS["_wait_job_suspended"](api, lab, N_LOW, LOW, False)
    fifo_released = (final.get("status", {}).get("admission", {}).get("clusterQueue") == CQ
                     and final_job.get("spec", {}).get("suspend") is False)
    raw["fifo_after_release"] = {"workload": final, "job": final_job}
    persist()
    lab.check("positive", "The younger low-use peer is admitted after FIFO's older reservation is released",
              fifo_released,
              {"younger_peer_admitted_after_release": fifo_released})
    raw["retired_final_fifo_job"] = AFS["_retire_owned_job"](
        api, lab, N_LOW, LOW, final)
    persist()
