"""Exercise synthetic locality labels and failure-domain spread on ordinary kind."""
import importlib.util
import json
from pathlib import Path
import time

from fixtures import BUSYBOX_IMAGE

POOL = "saf.example/node-pool"
NUMA = "saf.example/numa-fixture"
DOMAIN = "saf.example/failure-domain"
GROUP = "saf.example/spread-group"
SCOPE = (
    "Kubernetes v1.36.1 on a disposable three-node kind cluster. Synthetic worker labels "
    "exercise ordinary node-selector placement and Pod topology spread across two named "
    "failure domains. It withdraws one fixture worker from scheduling and checks Ready replica replacement and redistribution after return. The fixture does not configure kubelet Topology Manager, expose NUMA "
    "hardware or GPU resources, install a device plugin/vendor operator, or measure NVLink/"
    "NVSwitch connectivity or bandwidth. Production labels, hardware topology, plugin behavior, "
    "and workload fault tolerance require separate evidence."
)


def as_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def make_pod(name, *, selectors=None, group=None, spread=False):
    metadata = {"name": name}
    if group:
        metadata["labels"] = {GROUP: group}
    spec = {
        "automountServiceAccountToken": False,
        "restartPolicy": "Never",
        "terminationGracePeriodSeconds": 1,
        "containers": [{"name": "probe", "image": BUSYBOX_IMAGE, "command": ["sleep", "900"]}],
    }
    if selectors:
        spec["nodeSelector"] = selectors
    if spread:
        spec["topologySpreadConstraints"] = [{
            "maxSkew": 1,
            "topologyKey": DOMAIN,
            "whenUnsatisfiable": "DoNotSchedule",
            "nodeAffinityPolicy": "Ignore",
            "labelSelector": {"matchLabels": {GROUP: group}},
        }]
    return {"apiVersion": "v1", "kind": "Pod", "metadata": metadata, "spec": spec}


def pod_record(lab, name):
    return as_json(lab, "get", "pod", name)


def scheduled(record):
    return bool(record.get("spec", {}).get("nodeName"))


def running(record):
    return record.get("status", {}).get("phase") == "Running"


def wait_for(lab, name, predicate, seconds=30):
    end = time.monotonic() + seconds
    record = pod_record(lab, name)
    while time.monotonic() < end:
        if predicate(record):
            return record
        time.sleep(0.5)
        record = pod_record(lab, name)
    return record


def wait_running(lab, name):
    return wait_for(lab, name, running)


def unschedulable(lab, name):
    return wait_for(lab, name, lambda record: any(
        condition.get("type") == "PodScheduled" and condition.get("reason") == "Unschedulable"
        for condition in record.get("status", {}).get("conditions", [])
    ))


def node_domain(lab, name):
    node_name = pod_record(lab, name).get("spec", {}).get("nodeName")
    if not node_name:
        return None
    node = as_json(lab, "get", "node", node_name)
    return node.get("metadata", {}).get("labels", {}).get(DOMAIN)


def run(lab):
    nodes = as_json(lab, "get", "nodes")["items"]
    workers = [item for item in nodes if item.get("metadata", {}).get("labels", {}).get(POOL) == "compute"]
    domains = {item.get("metadata", {}).get("labels", {}).get(DOMAIN) for item in workers}
    aligned_nodes = [item["metadata"]["name"] for item in workers
                     if item.get("metadata", {}).get("labels", {}).get(NUMA) == "aligned"]
    lab.check("positive", "Fixture has two synthetic compute failure domains and one locality-labeled worker",
              len(workers) == 2 and domains == {"fd-a", "fd-b"} and len(aligned_nodes) == 1,
              {"compute_workers": len(workers), "failure_domains": sorted(str(value) for value in domains),
               "aligned_worker_count": len(aligned_nodes)})

    # Baseline: a benign Pod pinned to the synthetic non-locality domain runs without
    # a locality selector, demonstrating that the label requirement is not inherent.
    baseline = make_pod("saf-0703-013-baseline", selectors={POOL: "compute", DOMAIN: "fd-a"})
    lab.create(baseline)
    baseline_record = wait_running(lab, baseline["metadata"]["name"])
    lab.check("red", "Without a synthetic locality selector, a benign Pod runs in the unlabeled fixture domain",
              running(baseline_record) and node_domain(lab, baseline["metadata"]["name"]) == "fd-a",
              {"phase": baseline_record.get("status", {}).get("phase"),
               "assigned_domain": node_domain(lab, baseline["metadata"]["name"]),
               "locality_selector_present": False})

    local = make_pod("saf-0703-013-local", selectors={POOL: "compute", NUMA: "aligned"})
    lab.create(local)
    local_record = wait_running(lab, local["metadata"]["name"])
    local_node = local_record.get("spec", {}).get("nodeName")
    lab.check("positive", "A synthetic locality selector places the Pod only on the labeled worker",
              running(local_record) and local_node in aligned_nodes,
              {"scheduled": scheduled(local_record), "node_has_synthetic_locality_label": local_node in aligned_nodes,
               "selector": f"{NUMA}=aligned"})

    impossible = make_pod("saf-0703-013-no-local-match",
                          selectors={POOL: "compute", NUMA: "not-present"})
    lab.create(impossible)
    blocked = unschedulable(lab, impossible["metadata"]["name"])
    condition = next((item for item in blocked.get("status", {}).get("conditions", [])
                      if item.get("type") == "PodScheduled"), {})
    affinity_failure = (not scheduled(blocked) and condition.get("reason") == "Unschedulable"
                        and "node affinity/selector" in condition.get("message", "").lower())
    lab.check("negative", "A requested synthetic locality value absent from all workers remains unscheduled",
              affinity_failure,
              {"scheduled": scheduled(blocked), "reason": condition.get("reason"),
               "selector_failure_confirmed": affinity_failure})

    spread_names = [f"saf-0703-013-spread-{index}" for index in range(1, 5)]
    for name in spread_names:
        lab.create(make_pod(name, selectors={POOL: "compute"}, group="training-fixture", spread=True))
    spread_records = [wait_running(lab, name) for name in spread_names]
    counts = {domain: sum(node_domain(lab, name) == domain for name in spread_names) for domain in domains}
    all_running = all(running(record) for record in spread_records)
    lab.check("positive", "Topology spread places four matching Pods across both synthetic failure domains",
              all_running and counts == {"fd-a": 2, "fd-b": 2},
              {"domain_counts": counts, "all_running": all_running})

    # A required node selector still pins the next matching Pod to fd-a. Ignore
    # makes the spread calculation include both domains; the first extra Pod keeps
    # skew at one, while the following one must be rejected for spread alone.
    first_extra = make_pod("saf-0703-013-extra-a1",
                           selectors={POOL: "compute", DOMAIN: "fd-a"},
                           group="training-fixture", spread=True)
    lab.create(first_extra)
    extra_record = wait_running(lab, first_extra["metadata"]["name"])
    extra_domain = node_domain(lab, first_extra["metadata"]["name"])
    lab.check("positive", "One additional fd-a Pod is allowed while resulting skew remains one",
              running(extra_record) and extra_domain == "fd-a",
              {"scheduled": scheduled(extra_record), "assigned_domain": extra_domain})

    unconstrained = make_pod("saf-0703-013-extra-a2",
                             selectors={POOL: "compute", DOMAIN: "fd-a"}, group="training-fixture")
    lab.create(unconstrained)
    uncontrolled = wait_running(lab, unconstrained["metadata"]["name"])
    unconstrained_domain = node_domain(lab, unconstrained["metadata"]["name"])
    lab.check("red", "Without the spread constraint, the same second fd-a-only Pod runs at skew two",
              running(uncontrolled) and unconstrained_domain == "fd-a",
              {"running": running(uncontrolled), "assigned_domain": unconstrained_domain})
    lab.kubectl("delete", "pod", unconstrained["metadata"]["name"], "--wait=true", "--timeout=25s")

    second_extra = make_pod("saf-0703-013-extra-a2",
                            selectors={POOL: "compute", DOMAIN: "fd-a"},
                            group="training-fixture", spread=True)
    lab.create(second_extra)
    spread_block = unschedulable(lab, second_extra["metadata"]["name"])
    spread_condition = next((item for item in spread_block.get("status", {}).get("conditions", [])
                             if item.get("type") == "PodScheduled"), {})
    spread_denial = (not scheduled(spread_block) and spread_condition.get("reason") == "Unschedulable"
                     and "topology spread constraints" in spread_condition.get("message", "").lower())
    lab.check("green", "A second fd-a-only Pod is blocked because it would exceed maxSkew",
              spread_denial,
              {"scheduled": scheduled(spread_block), "reason": spread_condition.get("reason"),
               "spread_failure_confirmed": spread_denial, "nodeAffinityPolicy": "Ignore"})

    path = Path(__file__).resolve().with_name("domain_recovery.py")
    spec = importlib.util.spec_from_file_location("saf_0703_013_domain_recovery", path)
    recovery = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(recovery)
    recovery.run(lab)
