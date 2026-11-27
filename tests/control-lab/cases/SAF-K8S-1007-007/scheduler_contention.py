"""Bounded scheduler request and priority policy witness for SAF-K8S-1007-007."""
import json
import re
import time


NAMESPACE = "saf-1007-007-scheduler"
QUOTA = "saf-1007-007-scheduler-budget"
LOW_CLASS = "saf-1007-007-sched-holder"
NEVER_CLASS = "saf-1007-007-sched-never"
PREEMPT_CLASS = "saf-1007-007-sched-preempt"
WORKER_LABEL = "saf-lab.example/scheduler-target"
WORKER_VALUE = "owned"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
PODS = {
    "holder_never": "saf-1007-007-holder-never",
    "service_never": "saf-1007-007-service-never",
    "holder_preempt": "saf-1007-007-holder-preempt",
    "service_preempt": "saf-1007-007-service-preempt",
}


def _cpu_milli(value):
    value = str(value)
    if value.endswith("m"):
        return int(value[:-1])
    return int(float(value) * 1000)


def _cpu_request_milli(pod):
    spec = pod.get("spec", {})
    regular = {}
    for container in spec.get("containers", []):
        for resource, quantity in container.get("resources", {}).get("requests", {}).items():
            regular[resource] = regular.get(resource, 0) + (_cpu_milli(quantity) if resource == "cpu" else 0)
    init_max = {}
    for container in spec.get("initContainers", []):
        for resource, quantity in container.get("resources", {}).get("requests", {}).items():
            if resource == "cpu":
                init_max[resource] = max(init_max.get(resource, 0), _cpu_milli(quantity))
    return max(regular.get("cpu", 0), init_max.get("cpu", 0))


def _node_pods(lab, node):
    inventory = json.loads(lab.kubectl("get", "pods", "--all-namespaces", "-o", "json").stdout)
    return [pod for pod in inventory.get("items", [])
            if pod.get("spec", {}).get("nodeName") == node
            and pod.get("status", {}).get("phase") not in {"Succeeded", "Failed"}]


def _worker(lab):
    name = f"{lab.cluster}-worker"
    worker = json.loads(lab.kubectl("get", "node", name, "-o", "json").stdout)
    ready = any(condition.get("type") == "Ready" and condition.get("status") == "True"
                for condition in worker.get("status", {}).get("conditions", []))
    labels = worker.get("metadata", {}).get("labels", {})
    allocatable_m = _cpu_milli(worker.get("status", {}).get("allocatable", {}).get("cpu", "0"))
    return name, worker, ready, labels.get(WORKER_LABEL) == WORKER_VALUE, allocatable_m


def _priority(name, value, policy):
    return {"apiVersion": "scheduling.k8s.io/v1", "kind": "PriorityClass",
            "metadata": {"name": name, "labels": {"saf-lab.example/control": "SAF-K8S-1007-007"}},
            "value": value, "globalDefault": False, "preemptionPolicy": policy,
            "description": "Case-owned scheduler contention fixture only"}


def _pod(name, cpu_m, priority_class):
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": NAMESPACE,
                         "labels": {"saf-lab.example/control": "SAF-K8S-1007-007",
                                    "saf-lab.example/fixture": "scheduler-contention"}},
            "spec": {"priorityClassName": priority_class, "restartPolicy": "Never",
                     "terminationGracePeriodSeconds": 0, "automountServiceAccountToken": False,
                     "nodeSelector": {WORKER_LABEL: WORKER_VALUE},
                     "tolerations": [{"key": "saf-lab.example/scheduler-reserved", "operator": "Equal",
                                      "value": "true", "effect": "NoSchedule"}],
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "idle-holder", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                                     "command": ["python", "-B", "-c", "import time; time.sleep(3600)"],
                                     "securityContext": {"readOnlyRootFilesystem": True,
                                                         "allowPrivilegeEscalation": False,
                                                         "capabilities": {"drop": ["ALL"]}},
                                     "resources": {"requests": {"cpu": f"{cpu_m}m", "memory": "8Mi"},
                                                   "limits": {"cpu": f"{cpu_m}m", "memory": "64Mi"}}}]}}


def _create(lab, resource):
    return json.loads(lab.kubectl("-n", NAMESPACE, "create", "-f", "-", "-o", "json",
                                  payload=json.dumps(resource)).stdout)


def _get_pod(lab, name, *, absent_ok=False):
    args = ["-n", NAMESPACE, "get", "pod", name, "-o", "json"]
    if absent_ok:
        args.append("--ignore-not-found")
    result = lab.kubectl(*args)
    if absent_ok and (not result.stdout.strip() or result.stdout.strip() == "null"):
        return None
    return json.loads(result.stdout)


def _wait(lab, predicate, description, seconds=80):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(1)
    lab.block(description)


def _ready(pod):
    return (pod.get("status", {}).get("phase") == "Running"
            and any(item.get("type") == "Ready" and item.get("status") == "True"
                    for item in pod.get("status", {}).get("conditions", [])))


def _scheduled_condition(pod):
    return next((condition for condition in pod.get("status", {}).get("conditions", [])
                 if condition.get("type") == "PodScheduled"), {})


def _delete_uid(lab, name, uid):
    uri = f"/api/v1/namespaces/{NAMESPACE}/pods/{name}"
    options = {"apiVersion": "v1", "kind": "DeleteOptions", "gracePeriodSeconds": 0,
               "preconditions": {"uid": uid}}
    result = lab.kubectl("delete", "--raw", uri, "-f", "-", payload=json.dumps(options), timeout=25)
    return json.loads(result.stdout)


def _events(lab):
    return json.loads(lab.kubectl("-n", NAMESPACE, "get", "events", "-o", "json").stdout).get("items", [])


def _preemption_event(lab, victim_uid, preemptor_uid, preemptor_name):
    for event in _events(lab):
        obj = event.get("regarding") or event.get("involvedObject", {})
        controller = event.get("reportingController") or event.get("source", {}).get("component", "")
        reason = event.get("reason")
        message = event.get("note") or event.get("message") or ""
        if (obj.get("uid") == victim_uid and reason == "Preempted"
                and controller in {"default-scheduler", "kube-scheduler"}
                and (preemptor_uid in message or f"{NAMESPACE}/{preemptor_name}" in message)):
            return event
    return None


def _save_raw(lab, raw):
    (lab.evidence / "scheduler-contention-raw.json").write_text(
        json.dumps(raw, indent=2, sort_keys=True) + "\n")


def run(lab):
    worker_name, worker, node_ready, label_matches, allocatable_m = _worker(lab)
    node_pods = _node_pods(lab, worker_name)
    baseline_cpu_m = sum(_cpu_request_milli(pod) for pod in node_pods)
    other_pods_protected = all(int(pod.get("spec", {}).get("priority", 0)) >= 2000
                               for pod in node_pods)
    budget_ready = (node_ready and label_matches and allocatable_m == 1000
                    and 0 <= baseline_cpu_m <= 800 and other_pods_protected)
    lab.check("positive", "The case-owned worker reports the exact bounded CPU allocatable profile",
              budget_ready, {"worker_ready": node_ready, "target_label_matches": label_matches,
                             "one_cpu_allocatable": allocatable_m == 1000,
                             "bounded_baseline_requests": baseline_cpu_m <= 800,
                             "nonfixture_workers_protected": other_pods_protected})
    if not budget_ready:
        lab.block("The dedicated worker profile or existing request headroom differs from the reviewed fixture")

    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl("create", "-f", "-", payload=json.dumps(_priority(LOW_CLASS, 10, "Never")))
    lab.kubectl("create", "-f", "-", payload=json.dumps(_priority(NEVER_CLASS, 1000, "Never")))
    lab.kubectl("create", "-f", "-", payload=json.dumps(_priority(PREEMPT_CLASS, 2000, "PreemptLowerPriority")))
    quota_object = {"apiVersion": "v1", "kind": "ResourceQuota",
                    "metadata": {"name": QUOTA, "namespace": NAMESPACE,
                                 "labels": {"saf-lab.example/control": "SAF-K8S-1007-007"}},
                    "spec": {"hard": {"requests.cpu": "1500m", "requests.memory": "128Mi", "pods": "4"}}}
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(quota_object))
    quota = json.loads(lab.kubectl("-n", NAMESPACE, "get", "resourcequota", QUOTA, "-o", "json").stdout)
    classes = [json.loads(lab.kubectl("get", "priorityclass", name, "-o", "json").stdout)
               for name in (LOW_CLASS, NEVER_CLASS, PREEMPT_CLASS)]
    classes_match = ([item.get("value") for item in classes] == [10, 1000, 2000]
                     and [item.get("preemptionPolicy") for item in classes]
                     == ["Never", "Never", "PreemptLowerPriority"]
                     and all(item.get("globalDefault", False) is False for item in classes))
    quota_match = quota.get("spec", {}).get("hard") == {
        "requests.cpu": "1500m", "requests.memory": "128Mi", "pods": "4"}
    lab.check("positive", "The case-owned namespace quota and priority policies match the bounded comparison",
              classes_match and quota_match,
              {"three_scoped_priority_policies_match": classes_match, "fixture_quota_matches": quota_match})

    service_m = 250
    holder_m = min(800, 1000 - baseline_cpu_m - 100)
    if holder_m < 100 or baseline_cpu_m + holder_m > 1000 or baseline_cpu_m + holder_m + service_m <= 1000:
        lab.block("Observed worker requests leave no small deterministic holder/service scheduling margin")
    raw = {"worker": worker, "initial_worker_pods": node_pods, "baseline_cpu_request_milli": baseline_cpu_m,
           "holder_cpu_request_milli": holder_m, "service_cpu_request_milli": service_m,
           "quota": quota, "priority_classes": classes, "phases": {}}
    _save_raw(lab, raw)

    holder = _create(lab, _pod(PODS["holder_never"], holder_m, LOW_CLASS))
    holder_uid = holder.get("metadata", {}).get("uid")
    _wait(lab, lambda: _ready(_get_pod(lab, PODS["holder_never"])),
          "The low-priority case holder did not become Ready on the target worker")
    holder_live = _get_pod(lab, PODS["holder_never"])
    holder_ready = (_ready(holder_live) and holder_live.get("metadata", {}).get("uid") == holder_uid
                    and holder_live.get("spec", {}).get("nodeName") == worker_name
                    and holder_live.get("spec", {}).get("priority") == 10)
    raw["phases"]["first_holder"] = holder_live
    _save_raw(lab, raw)
    lab.check("positive", "The low-priority idle holder occupies only the measured target worker budget",
              holder_ready, {"holder_ready_on_target_worker": holder_ready,
                             "fixed_low_priority_resolved": holder_live.get("spec", {}).get("priority") == 10})

    never = _create(lab, _pod(PODS["service_never"], service_m, NEVER_CLASS))
    never_uid = never.get("metadata", {}).get("uid")
    def pending_never():
        pod = _get_pod(lab, PODS["service_never"])
        condition = _scheduled_condition(pod)
        return pod if condition.get("status") == "False" and condition.get("reason") == "Unschedulable" else None
    never_pending = _wait(lab, pending_never,
                          "The non-preempting service Pod did not reach the scheduler's Unschedulable state")
    never_condition = _scheduled_condition(never_pending)
    holder_unchanged = _get_pod(lab, PODS["holder_never"])
    exact_cpu_reason = "Insufficient cpu" in never_condition.get("message", "")
    holder_unchanged_ok = (_ready(holder_unchanged)
                           and holder_unchanged.get("metadata", {}).get("uid") == holder_uid
                           and not holder_unchanged.get("metadata", {}).get("deletionTimestamp"))
    raw["phases"]["never_blocked"] = {"holder": holder_unchanged, "service": never_pending,
                                       "pending_condition": never_condition, "events": _events(lab)}
    _save_raw(lab, raw)
    lab.check("positive", "The higher-priority Never Pod remains pending for Insufficient cpu without evicting its holder",
              exact_cpu_reason and holder_unchanged_ok and never_pending.get("metadata", {}).get("uid") == never_uid,
              {"scheduler_reports_insufficient_cpu": exact_cpu_reason,
               "same_holder_remains_ready": holder_unchanged_ok,
               "nonpreempting_service_is_pending": never_pending.get("status", {}).get("phase") == "Pending"})

    _delete_uid(lab, PODS["holder_never"], holder_uid)
    _wait(lab, lambda: _get_pod(lab, PODS["holder_never"], absent_ok=True) is None,
          "The first-phase holder UID did not retire after its exact deletion")
    _wait(lab, lambda: _ready(_get_pod(lab, PODS["service_never"])),
          "The non-preempting service did not schedule after capacity was voluntarily freed")
    never_ready = _get_pod(lab, PODS["service_never"])
    never_ready_ok = (_ready(never_ready) and never_ready.get("metadata", {}).get("uid") == never_uid
                      and never_ready.get("spec", {}).get("nodeName") == worker_name
                      and never_ready.get("spec", {}).get("priority") == 1000)
    raw["phases"]["never_released"] = {"holder_absent": True, "service": never_ready}
    _save_raw(lab, raw)
    lab.check("positive", "The same non-preempting service schedules on the target after exact holder removal",
              never_ready_ok, {"same_service_ready_on_target_worker": never_ready_ok,
                               "nonpreempting_priority_resolved": never_ready.get("spec", {}).get("priority") == 1000})
    _delete_uid(lab, PODS["service_never"], never_uid)
    _wait(lab, lambda: _get_pod(lab, PODS["service_never"], absent_ok=True) is None,
          "The first-phase service UID did not retire before the preemption phase")

    holder2 = _create(lab, _pod(PODS["holder_preempt"], holder_m, LOW_CLASS))
    holder2_uid = holder2.get("metadata", {}).get("uid")
    _wait(lab, lambda: _ready(_get_pod(lab, PODS["holder_preempt"])),
          "The second low-priority holder did not become Ready")
    raw["phases"]["second_holder"] = _get_pod(lab, PODS["holder_preempt"])
    _save_raw(lab, raw)
    before_victims = {pod.get("metadata", {}).get("uid") for pod in _node_pods(lab, worker_name)}
    preemptor = _create(lab, _pod(PODS["service_preempt"], service_m, PREEMPT_CLASS))
    preemptor_uid = preemptor.get("metadata", {}).get("uid")
    raw["phases"]["preemptor_submitted"] = preemptor
    _save_raw(lab, raw)
    attribution = _wait(lab, lambda: _preemption_event(lab, holder2_uid, preemptor_uid,
                                                        PODS["service_preempt"]),
                        "The scheduler did not emit a Preempted event naming the exact case preemptor")
    _wait(lab, lambda: _get_pod(lab, PODS["holder_preempt"], absent_ok=True) is None,
          "The exact preemption victim UID did not retire")
    _wait(lab, lambda: _ready(_get_pod(lab, PODS["service_preempt"])),
          "The case-owned preemptor did not become Ready after victim retirement")
    preemptor_live = _get_pod(lab, PODS["service_preempt"])
    remaining = _node_pods(lab, worker_name)
    remaining_uids = {pod.get("metadata", {}).get("uid") for pod in remaining}
    unexpected_retired = before_victims - remaining_uids - {holder2_uid}
    holder_absent = _get_pod(lab, PODS["holder_preempt"], absent_ok=True) is None
    event_subject = attribution.get("regarding") or attribution.get("involvedObject", {})
    event_message = attribution.get("note") or attribution.get("message") or ""
    event_controller = attribution.get("reportingController") or attribution.get("source", {}).get("component", "")
    event_exact = (event_subject.get("uid") == holder2_uid and attribution.get("reason") == "Preempted"
                   and event_controller in {"default-scheduler", "kube-scheduler"}
                   and (preemptor_uid in event_message
                        or f"{NAMESPACE}/{PODS['service_preempt']}" in event_message))
    replacement_ready = (_ready(preemptor_live) and preemptor_live.get("metadata", {}).get("uid") == preemptor_uid
                         and preemptor_live.get("spec", {}).get("nodeName") == worker_name
                         and preemptor_live.get("spec", {}).get("priority") == 2000)
    raw["phases"]["preemption"] = {"holder": holder2, "preemptor": preemptor_live,
                                    "victim_absent": holder_absent, "event": attribution,
                                    "worker_before_uids": sorted(before_victims),
                                    "worker_after_pods": remaining,
                                    "unexpected_retired_uids": sorted(unexpected_retired)}
    _save_raw(lab, raw)
    lab.check("positive", "The scheduler attributes preemption to the exact high-priority Pod and retires only its victim",
              event_exact and holder_absent and replacement_ready and not unexpected_retired,
              {"scheduler_preemption_event_exact": event_exact, "victim_uid_retired": holder_absent,
               "preemptor_ready_on_target_worker": replacement_ready,
               "no_other_initial_worker_pod_retired": not unexpected_retired})

    _delete_uid(lab, PODS["service_preempt"], preemptor_uid)
    _wait(lab, lambda: _get_pod(lab, PODS["service_preempt"], absent_ok=True) is None,
          "The preemptor UID did not retire during cleanup")
    current = _node_pods(lab, worker_name)
    cleanup_only_initial = {pod.get("metadata", {}).get("uid") for pod in current} >= before_victims - {holder2_uid}
    lab.kubectl("delete", "namespace", NAMESPACE, "--wait=true", "--timeout=50s", timeout=60)
    for name in (LOW_CLASS, NEVER_CLASS, PREEMPT_CLASS):
        lab.kubectl("delete", "priorityclass", name, "--wait=true")
    namespace_absent = lab.kubectl("get", "namespace", NAMESPACE, "-o", "json", "--ignore-not-found").stdout.strip() in {"", "null"}
    classes_absent = all(lab.kubectl("get", "priorityclass", name, "-o", "json", "--ignore-not-found").stdout.strip()
                         in {"", "null"} for name in (LOW_CLASS, NEVER_CLASS, PREEMPT_CLASS))
    lab.check("positive", "The bounded namespace and PriorityClasses are removed after the scoped comparison",
              cleanup_only_initial and namespace_absent and classes_absent,
              {"initial_unrelated_worker_pods_preserved": cleanup_only_initial,
               "owned_namespace_deleted": namespace_absent, "owned_classes_deleted": classes_absent})
    raw["cleanup"] = {"namespace_deleted": namespace_absent, "priority_classes_deleted": classes_absent,
                      "preemptor_deleted_by_uid": preemptor_uid}
    _save_raw(lab, raw)
