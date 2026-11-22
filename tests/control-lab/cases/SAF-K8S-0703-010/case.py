"""Observe cgroup v2 and CPU Manager static behavior on the same worker."""
import json
import time

from fixtures import container, pod, ready

POOL = "saf.example/node-pool"
TAINT = "saf.example/ai-pool"
BASE = "saf-0703-010-shared"
EXCLUSIVE = "saf-0703-010-exclusive"
SCOPE = (
    "Kubernetes v1.36.1 multi-node kind. A fractional Pod and one Guaranteed integer-CPU "
    "Pod have separate effective CPU sets on the same AI-labeled worker with kubelet "
    "CPU Manager static. The nonroot fractional Pod sees its cgroup v2 CPU and memory "
    "limits. NUMA, Memory Manager, interconnect, workload throughput and actual GPU "
    "or production node behavior require separate evidence."
)


def workload(name, cpus, *, tolerated=True, affinity=True):
    resources = {"memory": "32Mi", "cpu": cpus}
    resource = pod(name, [container("probe", resources={"requests": resources, "limits": resources})],
                   automountServiceAccountToken=False)
    if affinity:
        resource["spec"]["nodeSelector"] = {POOL: "ai"}
    if tolerated and affinity:
        resource["spec"]["tolerations"] = [
            {"key": TAINT, "operator": "Equal", "value": "reserved", "effect": "NoSchedule"},
        ]
    return resource


def as_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def node(lab, name):
    return as_json(lab, "get", "pod", name)["spec"].get("nodeName")


def cpus(text):
    result = set()
    for value in text.split(","):
        start, separator, end = value.partition("-")
        result.update(range(int(start), int(end) + 1) if separator else (int(start),))
    return result


def settings(lab, name):
    reply = lab.kubectl("exec", name, "--", "sh", "-ec",
                        "cd /sys/fs/cgroup; test -f cgroup.controllers; "
                        "cat cpuset.cpus.effective; cat cpu.max; cat memory.max")
    cpuset, budget, memory = reply.stdout.strip().splitlines()
    shares, period = budget.split()
    return cpus(cpuset), shares, int(period), int(memory)


def run(lab):
    for workload_name, cpu, opts in (
        (BASE, "100m", {}),
        ("saf-0703-010-general", "100m", {"affinity": False}),
        ("saf-0703-010-blocked", "100m", {"tolerated": False}),
    ):
        lab.create(workload(workload_name, cpu, **opts))
    ready(lab, BASE)
    ready(lab, "saf-0703-010-general")
    ai = node(lab, BASE)
    other = node(lab, "saf-0703-010-general")
    labels = {item["metadata"]["name"]: item["metadata"].get("labels", {}).get(POOL)
              for item in as_json(lab, "get", "nodes")["items"]}
    lab.check("positive", "AI-affine and ordinary Pods use separate fixture node pools",
              labels.get(ai) == "ai" and labels.get(other) == "general" and ai != other,
              {"ai_pool": labels.get(ai), "ordinary_pool": labels.get(other), "separate_nodes": ai != other})
    end = time.monotonic() + 20
    while True:
        record = as_json(lab, "get", "pod", "saf-0703-010-blocked")
        scheduling = next((item for item in record.get("status", {}).get("conditions", [])
                           if item["type"] == "PodScheduled"), {})
        refused = (not record["spec"].get("nodeName") and scheduling.get("reason") == "Unschedulable"
                   and "untolerated taint" in scheduling.get("message", "").lower())
        if refused or time.monotonic() >= end:
            break
        time.sleep(0.5)
    lab.check("green", "An AI-affine Pod lacking the required toleration remains unscheduled",
              refused, {"scheduled": bool(record["spec"].get("nodeName")),
                        "reason": scheduling.get("reason"), "taint_confirmed": refused})

    shared_before, budget, period, memory = settings(lab, BASE)
    lab.check("red", "Placement alone leaves the fractional Pod in a shared CPU pool",
              len(shared_before) >= 2, {"shared_cpu_set_contains_multiple_cpus": len(shared_before) >= 2})
    cpu_bounded = budget.isdecimal() and int(budget) * 10 == period
    lab.check("green", "The live nonroot Pod sees the declared CPU and memory bounds in cgroup v2",
              cpu_bounded and memory == 32 * 1024 * 1024,
              {"cpu_fraction_matches": cpu_bounded, "memory_bytes": memory, "cgroup": "v2"})

    lab.create(workload(EXCLUSIVE, "1"))
    ready(lab, EXCLUSIVE)
    reserved, _, _, reserved_memory = settings(lab, EXCLUSIVE)
    end = time.monotonic() + 20
    while True:
        shared_after, _, _, _ = settings(lab, BASE)
        if reserved.isdisjoint(shared_after) or time.monotonic() >= end:
            break
        time.sleep(0.5)
    guarantee = as_json(lab, "get", "pod", EXCLUSIVE)["status"].get("qosClass")
    separated = reserved.isdisjoint(shared_after)
    same_node = ai == node(lab, EXCLUSIVE)
    lab.check("positive", "CPU Manager assigns one exclusive CPU and removes it from the colocated shared pool",
              guarantee == "Guaranteed" and same_node and len(reserved) == 1
              and reserved <= shared_before and bool(shared_after) and separated
              and reserved_memory == 32 * 1024 * 1024,
              {"qos_class": guarantee, "same_ai_node": same_node, "exclusive_cpu_count": len(reserved),
               "exclusive_cpu_removed_from_shared_pool": separated, "exclusive_pod_memory_bytes": reserved_memory})
