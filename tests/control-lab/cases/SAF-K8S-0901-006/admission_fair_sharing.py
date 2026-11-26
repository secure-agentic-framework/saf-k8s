"""Bounded CPU-only Kueue v0.17.7 Admission Fair Sharing witness."""
from datetime import datetime
import json
import runpy
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
QUEUE_CASE = HERE / "queue_admission.py"
IMAGE = (
    "docker.io/library/busybox:1.37.0@"
    "sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
CONTROLLER_IMAGE = (
    "registry.k8s.io/kueue/kueue:v0.17.7@"
    "sha256:de23a924bf8f2df2ff5553a660c1032b7c48ebabd4a551750d0e997819001663"
)
CONFIG_NAME = "kueue-manager-config"
CONFIG_KEY = "controller_manager_config.yaml"
CONFIG_EXCERPT = (
    "admissionFairSharing:\n"
    "  usageHalfLifeTime: 30s\n"
    "  usageSamplingInterval: 1s"
)
HALF_LIFE_SECONDS = 30
SAMPLE_INTERVAL_SECONDS = 1
SUFFIX = "0901-006-afs"
MATCH_LABEL = "saf-k8s.io/admission-fair-sharing"
NS_HIGH = f"saf-{SUFFIX}-high"
NS_LOW = f"saf-{SUFFIX}-low"
NS_HOLDER = f"saf-{SUFFIX}-holder"
CQ = f"saf-cq-{SUFFIX}"
FLAVOR = f"saf-flavor-{SUFFIX}"
LQ_HIGH = f"saf-lq-{SUFFIX}-high"
LQ_LOW = f"saf-lq-{SUFFIX}-low"
LQ_HOLDER = f"saf-lq-{SUFFIX}-holder"
QUEUE_LABEL = "kueue.x-k8s.io/queue-name"
SEED_JOB = f"saf-{SUFFIX}-usage-seed"
HOLDER_JOB = f"saf-{SUFFIX}-quota-holder"
HIGH_JOB = f"saf-{SUFFIX}-high-usage-candidate"
LOW_JOB = f"saf-{SUFFIX}-low-usage-candidate"


def _api():
    return runpy.run_path(str(QUEUE_CASE))


def _cpu_millicores(quantity):
    """Convert Kubernetes CPU quantities into a comparison-only float."""
    text = str(quantity or "0").strip()
    try:
        if text.endswith("m"):
            return float(text[:-1])
        if text.endswith("u"):
            return float(text[:-1]) / 1000
        if text.endswith("n"):
            return float(text[:-1]) / 1_000_000
        return float(text) * 1000
    except ValueError:
        return 0.0


def _timestamp(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _usage_record(api, lab, namespace, local_queue):
    obj = api["_json"](lab, "get", "localqueue", local_queue, "-n", namespace)
    fair = obj.get("status", {}).get("fairSharing", {})
    afs = fair.get("admissionFairSharingStatus", {})
    consumed = afs.get("consumedResources", {})
    return {
        "queue_uid": obj.get("metadata", {}).get("uid"),
        "resource_version": obj.get("metadata", {}).get("resourceVersion"),
        "cpu_quantity": str(consumed.get("cpu", "0")),
        "cpu_millicores": _cpu_millicores(consumed.get("cpu", "0")),
        "last_update": afs.get("lastUpdate"),
        "fair_sharing_present": bool(fair),
    }


def _wait_workload(api, lab, namespace, job, quota_reserved, seconds=45):
    expected = "True" if quota_reserved else "False"
    name = job["metadata"]["name"]

    def observed():
        live_job_text = api["_kubectl"](
            lab, "get", "job", name, "-n", namespace, "-o", "json", check=False)
        if not live_job_text:
            return None
        live_job = json.loads(live_job_text)
        workload = api["_owned_workload"](lab, namespace, live_job)
        if not workload:
            return None
        condition = api["_condition"](workload, "QuotaReserved")
        if condition and condition.get("status") == expected:
            return workload
        return None

    return api["_wait"](lab, observed,
                        f"Workload {name} QuotaReserved={expected}",
                        seconds=seconds)


def _wait_job_suspended(api, lab, namespace, name, suspended, seconds=20):
    return api["_wait"](lab, lambda: (
        obj if (obj := api["_json"](lab, "get", "job", name, "-n", namespace))
        and obj.get("spec", {}).get("suspend") is suspended else None
    ), f"Job {name} suspend={suspended}", seconds=seconds)


def _wait_job_pod_ready(api, lab, namespace, name, seconds=75):
    """Wait for one Ready Pod owned by this live Job UID, tolerating delayed creation."""
    def observed():
        job = api["_json"](lab, "get", "job", name, "-n", namespace)
        uid = job.get("metadata", {}).get("uid")
        if not uid:
            return None
        pods = api["_json"](lab, "get", "pods", "-n", namespace,
                            "-l", f"app={name}").get("items", [])
        owned = [pod for pod in pods if any(
            owner.get("kind") == "Job" and owner.get("uid") == uid
            and owner.get("controller") is True
            for owner in pod.get("metadata", {}).get("ownerReferences", []))]
        if len(owned) != 1:
            return None
        pod = owned[0]
        ready = any(condition.get("type") == "Ready" and condition.get("status") == "True"
                    for condition in pod.get("status", {}).get("conditions", []))
        if pod.get("status", {}).get("phase") == "Running" and ready:
            return {"job": job, "pod": pod}
        return None

    return api["_wait"](lab, observed,
                        f"exact Job-owned Pod for {name} to become Ready",
                        seconds=seconds)


def _fixture_job(api, namespace, name, queue, seconds):
    job = api["_job"](namespace, name, IMAGE, "100m")
    job["metadata"]["labels"][QUEUE_LABEL] = queue
    job["spec"]["parallelism"] = 1
    job["spec"]["completions"] = 1
    job["spec"]["activeDeadlineSeconds"] = 180
    job["spec"]["template"]["spec"]["containers"][0]["command"] = [
        "/bin/sh", "-c", f"sleep {seconds}; printf '%s\\n' fair-share-fixture",
    ]
    return job


def _check_installed_config(api, lab):
    config = api["_json"](lab, "get", "configmap", CONFIG_NAME, "-n", "kueue-system")
    text = config.get("data", {}).get(CONFIG_KEY, "")
    if CONFIG_EXCERPT not in text:
        lab.block("The pinned installation did not retain the explicit AFS sampling settings")
    deployment = api["_json"](lab, "get", "deployment", "kueue-controller-manager", "-n", "kueue-system")
    containers = deployment.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
    if len(containers) != 1 or containers[0].get("image") != CONTROLLER_IMAGE:
        lab.block("The fair-sharing fixture is not using the exact pinned Kueue controller digest")
    # The source manifest is transformed before the controller is first created.
    # Its normal installation rollout loads this ConfigMap; no second restart is needed.
    return {"config_resource_version": config.get("metadata", {}).get("resourceVersion"),
            "config_excerpt": CONFIG_EXCERPT,
            "controller_image": containers[0]["image"]}


def _create_topology(api, lab):
    for namespace in (NS_HIGH, NS_LOW, NS_HOLDER):
        api["_apply"](lab, {"apiVersion": "v1", "kind": "Namespace",
                            "metadata": {"name": namespace, "labels": {MATCH_LABEL: SUFFIX}}})
    api["_apply"](lab, {"apiVersion": "kueue.x-k8s.io/v1beta2", "kind": "ResourceFlavor",
                        "metadata": {"name": FLAVOR}, "spec": {}})
    api["_apply"](lab, {
        "apiVersion": "kueue.x-k8s.io/v1beta2", "kind": "ClusterQueue",
        "metadata": {"name": CQ},
        "spec": {
            "namespaceSelector": {"matchLabels": {MATCH_LABEL: SUFFIX}},
            "queueingStrategy": "StrictFIFO",
            "admissionScope": {"admissionMode": "UsageBasedAdmissionFairSharing"},
            "resourceGroups": [{"coveredResources": ["cpu"], "flavors": [{
                "name": FLAVOR,
                "resources": [{"name": "cpu", "nominalQuota": "100m"}],
            }]}],
        },
    })
    for namespace, local_queue in ((NS_HIGH, LQ_HIGH), (NS_LOW, LQ_LOW), (NS_HOLDER, LQ_HOLDER)):
        api["_apply"](lab, {
            "apiVersion": "kueue.x-k8s.io/v1beta2", "kind": "LocalQueue",
            "metadata": {"name": local_queue, "namespace": namespace},
            "spec": {"clusterQueue": CQ, "fairSharing": {"weight": "1"}},
        })
    return api["_wait"](lab, lambda: (
        obj if (obj := api["_json"](lab, "get", "clusterqueue", CQ))
        and any(c.get("type") == "Active" and c.get("status") == "True"
                for c in obj.get("status", {}).get("conditions", [])) else None
    ), "the isolated fair-sharing ClusterQueue to become Active")


def _retire_owned_job(api, lab, namespace, name, workload):
    """Observe fixture cleanup before the shared readiness gate sees the next phase."""
    job = api["_json"](lab, "get", "job", name, "-n", namespace)
    job_uid = job["metadata"]["uid"]
    workload_uid = workload["metadata"]["uid"]
    owners = workload["metadata"].get("ownerReferences", [])
    if not any(owner.get("kind") == "Job" and owner.get("uid") == job_uid for owner in owners):
        lab.block("The fixture Workload does not reference the exact Job to retire")
    api["_kubectl"](lab, "delete", "job", name, "-n", namespace,
                    "--cascade=foreground", "--wait=true", timeout=45)

    def workload_removed():
        remaining = api["_json"](lab, "get", "workloads.kueue.x-k8s.io", "-n", namespace)
        return not any(item.get("metadata", {}).get("uid") == workload_uid
                       for item in remaining.get("items", []))

    api["_wait"](lab, workload_removed, "the retired fixture Workload UID to disappear", seconds=30)
    return {"job_uid": job_uid, "workload_uid": workload_uid, "removed": True}


def run(lab):
    api = _api()
    evidence = {"installed": _check_installed_config(api, lab)}
    cluster_queue = _create_topology(api, lab)
    evidence["cluster_queue"] = {
        "uid": cluster_queue["metadata"]["uid"],
        "resource_version": cluster_queue["metadata"]["resourceVersion"],
        "admission_scope": cluster_queue["spec"]["admissionScope"],
        "queueing_strategy": cluster_queue["spec"]["queueingStrategy"],
        "nominal_cpu": "100m",
    }
    lab.check("positive", "Pinned Kueue starts with explicit sampled AFS configuration",
              evidence["installed"]["controller_image"] == CONTROLLER_IMAGE,
              {"pinned_controller": True,
               "explicit_half_life_configured": True,
               "explicit_one_second_sample_interval": True,
               "installation_rollout_loaded_config": True})

    seed = _fixture_job(api, NS_HIGH, SEED_JOB, LQ_HIGH, seconds=20)
    api["_apply"](lab, seed)
    seed_workload = _wait_workload(api, lab, NS_HIGH, seed, quota_reserved=True)
    seed_reservation = api["_condition"](seed_workload, "QuotaReserved")
    seed_pod = _wait_job_pod_ready(api, lab, NS_HIGH, SEED_JOB)

    def sampled_after_admission():
        usage = _usage_record(api, lab, NS_HIGH, LQ_HIGH)
        sample_time = _timestamp(usage["last_update"])
        reservation_time = _timestamp(seed_reservation.get("lastTransitionTime"))
        fresh = bool(sample_time and reservation_time
                     and (sample_time - reservation_time).total_seconds() >= 3)
        if usage["cpu_millicores"] > 0 and fresh:
            return usage
        return None

    sampled_high = api["_wait"](lab, sampled_after_admission,
                                "multiple fresh positive AFS samples from the admitted seed",
                                seconds=25)
    seed_job = api["_json"](lab, "get", "job", SEED_JOB, "-n", NS_HIGH)
    api["_wait"](lab, lambda: (
        obj if (obj := api["_json"](lab, "get", "job", SEED_JOB, "-n", NS_HIGH))
        and any(c.get("type") == "Complete" and c.get("status") == "True"
                for c in obj.get("status", {}).get("conditions", [])) else None
    ), "the inert historical-use seed Job to complete", seconds=40)

    high_usage = _usage_record(api, lab, NS_HIGH, LQ_HIGH)
    low_usage = _usage_record(api, lab, NS_LOW, LQ_LOW)
    history_is_distinct = high_usage["cpu_millicores"] > 0 and low_usage["cpu_millicores"] == 0
    if not history_is_distinct:
        lab.block("A fresh high-use versus zero-use LocalQueue history was not observed")
    lab.check("positive", "Kueue reports sampled historical CPU use only on the seeded LocalQueue",
              history_is_distinct,
              {"seeded_queue_has_positive_history": True,
               "unseeded_queue_has_zero_history": True,
               "sample_is_after_seed_admission": True})
    evidence["seed"] = {
        "job_uid": seed_job["metadata"]["uid"],
        "workload_uid": seed_workload["metadata"]["uid"],
        "quota_reserved": seed_reservation,
        "ready_pod": seed_pod,
        "sampled_during_admission": sampled_high,
        "high_usage_after_completion": high_usage,
        "low_usage_before_competition": low_usage,
    }

    holder = _fixture_job(api, NS_HOLDER, HOLDER_JOB, LQ_HOLDER, seconds=120)
    api["_apply"](lab, holder)
    holder_workload = _wait_workload(api, lab, NS_HOLDER, holder, quota_reserved=True)
    holder_pod = _wait_job_pod_ready(api, lab, NS_HOLDER, HOLDER_JOB)

    older_high_job = _fixture_job(api, NS_HIGH, HIGH_JOB, LQ_HIGH, seconds=45)
    api["_apply"](lab, older_high_job)
    older_high = _wait_workload(api, lab, NS_HIGH, older_high_job, quota_reserved=False)
    older_high_job_live = api["_json"](lab, "get", "job", HIGH_JOB, "-n", NS_HIGH)
    # Kubernetes creationTimestamp is commonly serialized at one-second
    # precision; force distinct timestamps so "older" is a real observation.
    time.sleep(1.2)
    newer_low_job = _fixture_job(api, NS_LOW, LOW_JOB, LQ_LOW, seconds=45)
    api["_apply"](lab, newer_low_job)
    newer_low = _wait_workload(api, lab, NS_LOW, newer_low_job, quota_reserved=False)
    newer_low_job_live = api["_json"](lab, "get", "job", LOW_JOB, "-n", NS_LOW)
    older_time = _timestamp(older_high.get("metadata", {}).get("creationTimestamp"))
    newer_time = _timestamp(newer_low.get("metadata", {}).get("creationTimestamp"))
    same_priority = older_high.get("spec", {}).get("priority", 0) == newer_low.get("spec", {}).get("priority", 0)
    older_high_candidate = bool(older_time and newer_time and older_time < newer_time)
    if not same_priority or not older_high_candidate:
        lab.block("The competing candidate Workloads are not equal-priority and ordered as designed")
    evidence["competition"] = {
        "holder_workload_uid": holder_workload["metadata"]["uid"],
        "holder_ready_pod": holder_pod,
        "older_high_job_uid": older_high_job_live["metadata"]["uid"],
        "newer_low_job_uid": newer_low_job_live["metadata"]["uid"],
        "older_high_workload": older_high,
        "newer_low_workload": newer_low,
        "same_priority": same_priority,
        "high_candidate_older": older_high_candidate,
    }
    lab.check("positive", "Equal-priority candidates are held behind one reservation, with the high-use candidate older",
              same_priority and older_high_candidate,
              {"both_candidates_held": True,
               "candidate_priority_equal": same_priority,
               "high_use_candidate_created_first": True,
               "nominal_cpu_quota_fully_reserved": True})

    pre_release_high = _usage_record(api, lab, NS_HIGH, LQ_HIGH)
    pre_release_low = _usage_record(api, lab, NS_LOW, LQ_LOW)
    pre_release_history_distinct = (
        pre_release_high["cpu_millicores"] > pre_release_low["cpu_millicores"]
        and pre_release_low["cpu_millicores"] == 0
    )
    if not pre_release_history_distinct:
        lab.block("The high-use queue history decayed or disappeared before the selection boundary")
    evidence["pre_release_history"] = {"high": pre_release_high, "low": pre_release_low}
    lab.check("positive", "The actual high-use versus zero-use history remains distinct immediately before quota release",
              pre_release_history_distinct,
              {"high_use_still_positive": True, "low_use_still_zero": True})

    api["_kubectl"](lab, "delete", "job", HOLDER_JOB, "-n", NS_HOLDER, "--wait=true", timeout=45)
    selected_low = _wait_workload(api, lab, NS_LOW, newer_low_job, quota_reserved=True, seconds=40)
    still_pending_high = _wait_workload(api, lab, NS_HIGH, older_high_job, quota_reserved=False, seconds=15)
    selected_job = _wait_job_suspended(api, lab, NS_LOW, LOW_JOB, False)
    high_job_now = _wait_job_suspended(api, lab, NS_HIGH, HIGH_JOB, True)
    high_still_pending = (
        still_pending_high.get("spec", {}).get("queueName") == LQ_HIGH
        and api["_condition"](still_pending_high, "QuotaReserved").get("status") == "False"
        and high_job_now.get("spec", {}).get("suspend") is True
    )
    lower_use_won = (
        selected_low.get("spec", {}).get("queueName") == LQ_LOW
        and selected_low.get("status", {}).get("admission", {}).get("clusterQueue") == CQ
        and high_still_pending
        and selected_job.get("spec", {}).get("suspend") is False
    )
    lab.check("green", "Kueue admits the lower-use newer queue before the older high-use peer",
              lower_use_won,
              {"lower_use_queue_admitted_first": lower_use_won,
               "older_high_use_queue_still_pending": high_still_pending,
               "cluster_queue_match": selected_low.get("status", {}).get("admission", {}).get("clusterQueue") == CQ})
    evidence["first_admission"] = {
        "selected_workload": selected_low,
        "still_pending_workload": still_pending_high,
        "selected_job": selected_job,
        "high_job": high_job_now,
    }

    api["_kubectl"](lab, "delete", "job", LOW_JOB, "-n", NS_LOW, "--wait=true", timeout=45)
    eventual_high = _wait_workload(api, lab, NS_HIGH, older_high_job, quota_reserved=True, seconds=40)
    released_then_admitted = eventual_high.get("status", {}).get("admission", {}).get("clusterQueue") == CQ
    lab.check("positive", "The older high-use peer is admitted after the first reservation is released",
              released_then_admitted,
              {"older_peer_admitted_after_release": released_then_admitted,
               "expected_cluster_queue": True})
    evidence["after_release"] = {"high_workload": eventual_high}
    evidence["retired_before_fifo"] = _retire_owned_job(api, lab, NS_HIGH, HIGH_JOB, eventual_high)

    # This raw record intentionally preserves dynamic quantities and timestamps;
    # lab.check observations above remain normalized across the paired runs.
    (lab.evidence / "kueue-admission-fair-sharing-raw.json").write_text(
        json.dumps(evidence, sort_keys=True, indent=2) + "\n")

