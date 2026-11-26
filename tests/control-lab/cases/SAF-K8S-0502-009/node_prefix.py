"""Exercise native RangeAllocator exhaustion and release on owned synthetic Nodes."""
import json
import time
from ipaddress import ip_network


POD_POOL = ip_network("10.244.250.0/27")
NODE_MASK = 28
NODE_PREFIXES = tuple(POD_POOL.subnets(new_prefix=NODE_MASK))
OWNER_KEY = "saf-lab.example/owner"
OWNER_VALUE = "0502-009-nodeipam"
TAINT_KEY = "saf-lab.example/fixture-unschedulable"
FILLER = "saf-0502-009-nodeipam-filler"
SENTINEL = "saf-0502-009-nodeipam-sentinel"


def _nodes(lab):
    return json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]


def _node(lab, name):
    return json.loads(lab.kubectl("get", "node", name, "-o", "json").stdout)


def _node_cidr(item):
    values = item.get("spec", {}).get("podCIDRs", [])
    single = item.get("spec", {}).get("podCIDR", "")
    if single and values and values != [single]:
        return None
    return single or (values[0] if len(values) == 1 else "")


def _has_no_cidr(item):
    spec = item.get("spec", {})
    return not spec.get("podCIDR") and not spec.get("podCIDRs")


def _is_unschedulable(item):
    spec = item.get("spec", {})
    return (spec.get("unschedulable") is True
            and any(taint.get("key") == TAINT_KEY and taint.get("effect") == "NoSchedule"
                    for taint in spec.get("taints", [])))


def _unschedulable_node(name):
    return {
        "apiVersion": "v1", "kind": "Node",
        "metadata": {"name": name, "labels": {OWNER_KEY: OWNER_VALUE}},
        "spec": {
            "unschedulable": True,
            "taints": [{"key": TAINT_KEY, "value": "true", "effect": "NoSchedule"}],
        },
    }


def _no_pods_assigned(lab, names):
    items = json.loads(lab.kubectl("get", "pods", "-A", "-o", "json").stdout)["items"]
    return not any(item.get("spec", {}).get("nodeName") in names for item in items)


def _allocator_event(lab, name, uid):
    items = json.loads(lab.kubectl("get", "events", "-A", "-o", "json").stdout)["items"]
    for event in items:
        target = event.get("involvedObject", {})
        if (target.get("kind") == "Node" and target.get("name") == name
                and target.get("uid") == uid and event.get("reason") == "CIDRNotAvailable"):
            return {
                "event_uid_matches_exact_node": True,
                "native_reason_matches": True,
                "native_type_matches": event.get("type") == "Normal",
                "native_allocator_source_matches": (
                    event.get("source", {}).get("component") == "cidrAllocator"),
            }
    return {"event_uid_matches_exact_node": False,
            "native_reason_matches": False, "native_type_matches": False,
            "native_allocator_source_matches": False}


def _wait_node(lab, name, uid, accept, *, event=False, timeout=35):
    deadline = time.monotonic() + timeout
    latest = None
    while time.monotonic() < deadline:
        item = _node(lab, name)
        latest = {"node_has_no_podcidr": _has_no_cidr(item),
                  "node_cidr_is_expected_released_prefix": (
                      _node_cidr(item) == str(NODE_PREFIXES[1]))}
        if event:
            latest.update(_allocator_event(lab, name, uid))
        if accept(item, latest):
            return item, latest
        time.sleep(0.35)
    return item, latest or {}


def _controller_manager_flags(lab):
    name = f"kube-controller-manager-{lab.cluster}-control-plane"
    item = json.loads(lab.kubectl(
        "get", "pod", "-n", "kube-system", name, "-o", "json").stdout)
    containers = [container for container in item.get("spec", {}).get("containers", [])
                  if container.get("name") == "kube-controller-manager"]
    if len(containers) != 1:
        lab.block("Owned controller-manager static Pod is not uniquely identifiable")
    return set(containers[0].get("command", []))


def run_node_prefix_allocator_recovery(lab, route):
    """Use two inert Node API objects to exercise native allocation, release, and retry."""
    if len(NODE_PREFIXES) != 2 or NODE_PREFIXES[0].prefixlen != NODE_MASK:
        lab.block("The reviewed two-slot node-prefix fixture is malformed")
    flags = _controller_manager_flags(lab)
    required_flags = {
        "--allocate-node-cidrs=true",
        f"--cluster-cidr={POD_POOL}",
        f"--node-cidr-mask-size-ipv4={NODE_MASK}",
    }
    if not required_flags <= flags:
        lab.block("The owned controller-manager does not have the pinned node CIDR settings")

    initial_nodes = _nodes(lab)
    control_plane_name = f"{lab.cluster}-control-plane"
    control_planes = [item for item in initial_nodes
                      if item.get("metadata", {}).get("name") == control_plane_name]
    if len(control_planes) != 1 or len(initial_nodes) != 1:
        lab.block("Synthetic Node IPAM witness requires exactly the owned Kind control plane")
    control_plane_cidr = _node_cidr(control_planes[0])
    if control_plane_cidr != str(NODE_PREFIXES[0]):
        lab.block("The control plane did not receive the expected first /28 PodCIDR")
    if (not route(lab, "capacity-original")
            or lab.kubectl("get", "--raw", "/readyz").stdout.strip() != "ok"):
        lab.block("The owned API or original case marker is not healthy before NodeIPAM proof")
    if any(item.get("metadata", {}).get("name") in {FILLER, SENTINEL}
           for item in initial_nodes):
        lab.block("A fixed-name synthetic Node already exists in the owned fixture")

    lab.check(
        "positive", "Owned controller-manager is configured for a two-prefix IPv4 pool",
        required_flags <= flags and control_plane_cidr == str(NODE_PREFIXES[0]),
        {"native_range_allocator_configured": True,
         "control_plane_consumes_one_of_two_prefixes": True,
         "api_and_original_marker_healthy": True})

    owned = set()
    filler_uid = None
    sentinel_uid = None
    try:
        filler = lab.create(_unschedulable_node(FILLER))
        owned.add(FILLER)
        filler_uid = filler["metadata"]["uid"]
        filler, _filler_state = _wait_node(
            lab, FILLER, filler_uid,
            lambda item, state: _node_cidr(item) == str(NODE_PREFIXES[1]))
        filler_safe = (filler.get("metadata", {}).get("uid") == filler_uid
                       and filler.get("metadata", {}).get("labels", {}).get(OWNER_KEY) == OWNER_VALUE
                       and _node_cidr(filler) == str(NODE_PREFIXES[1])
                       and _is_unschedulable(filler))
        if not filler_safe:
            lab.block("The owned filler Node did not receive the second prefix while remaining unschedulable")

        sentinel = lab.create(_unschedulable_node(SENTINEL))
        owned.add(SENTINEL)
        sentinel_uid = sentinel["metadata"]["uid"]
        sentinel, exhausted = _wait_node(
            lab, SENTINEL, sentinel_uid,
            lambda item, state: (state.get("event_uid_matches_exact_node")
                                 and state.get("native_reason_matches")
                                 and state.get("native_type_matches")
                                 and state.get("native_allocator_source_matches")),
            event=True)
        exhausted_ok = (
            _has_no_cidr(sentinel)
            and sentinel.get("metadata", {}).get("labels", {}).get(OWNER_KEY) == OWNER_VALUE
            and _is_unschedulable(sentinel)
            and _is_unschedulable(_node(lab, FILLER))
            and exhausted.get("event_uid_matches_exact_node")
            and exhausted.get("native_reason_matches")
            and exhausted.get("native_type_matches")
            and exhausted.get("native_allocator_source_matches")
            and _node_cidr(_node(lab, FILLER)) == str(NODE_PREFIXES[1])
            and _node_cidr(_node(lab, control_plane_name)) == str(NODE_PREFIXES[0])
            and _no_pods_assigned(lab, {FILLER, SENTINEL})
        )
        both_prefixes_filled = (
            _node_cidr(_node(lab, FILLER)) == str(NODE_PREFIXES[1])
            and _node_cidr(_node(lab, control_plane_name)) == str(NODE_PREFIXES[0]))
        lab.check(
            "red", "Native NodeIPAM reports CIDRNotAvailable for the exact unschedulable sentinel Node",
            exhausted_ok,
            {"two_distinct_node_prefixes_already_assigned": both_prefixes_filled,
             "sentinel_podcidr_absent": _has_no_cidr(sentinel),
             "native_event_uid_matches_sentinel": exhausted.get("event_uid_matches_exact_node", False),
             "native_reason_is_CIDRNotAvailable": exhausted.get("native_reason_matches", False),
             "native_event_type_is_Normal": exhausted.get("native_type_matches", False),
             "native_allocator_source_matches": exhausted.get("native_allocator_source_matches", False),
             "no_pods_assigned_to_synthetic_nodes": _no_pods_assigned(lab, {FILLER, SENTINEL})})

        if exhausted_ok:
            lab.kubectl("delete", "node", FILLER, "--wait=true", "--timeout=25s", timeout=32)
            owned.remove(FILLER)
            sentinel, _recovered = _wait_node(
                lab, SENTINEL, sentinel_uid,
                lambda item, state: _node_cidr(item) == str(NODE_PREFIXES[1]))
            recovered_ok = (
                _node_cidr(sentinel) == str(NODE_PREFIXES[1])
                and sentinel["metadata"]["uid"] == sentinel_uid
                and sentinel.get("metadata", {}).get("labels", {}).get(OWNER_KEY) == OWNER_VALUE
                and _is_unschedulable(sentinel)
                and len([item for item in _nodes(lab) if _node_cidr(item)]) == 2
                and _no_pods_assigned(lab, {SENTINEL})
                and route(lab, "capacity-original")
                and lab.kubectl("get", "--raw", "/readyz").stdout.strip() == "ok"
            )
            lab.check(
                "green", "Deleting the owned filler releases the same /28 to the waiting sentinel Node",
                recovered_ok,
                {"same_node_uid_reused_released_prefix": recovered_ok,
                 "released_prefix_reassigned": _node_cidr(sentinel) == str(NODE_PREFIXES[1]),
                 "sentinel_remains_unschedulable": _is_unschedulable(sentinel),
                 "no_pods_assigned_to_sentinel": _no_pods_assigned(lab, {SENTINEL}),
                 "api_and_original_marker_healthy": recovered_ok})
    finally:
        if owned:
            lab.kubectl("delete", "node", *sorted(owned), "--ignore-not-found=true",
                        "--wait=true", "--timeout=25s", timeout=32, allow_failure=True)
        final_nodes = _nodes(lab)
        synthetic_absent = not any(
            item.get("metadata", {}).get("name") in {FILLER, SENTINEL}
            for item in final_nodes)
        prefix_baseline_restored = (
            len(final_nodes) == 1
            and _node_cidr(final_nodes[0]) == control_plane_cidr
        )
        api_and_marker = (
            lab.kubectl("get", "--raw", "/readyz").stdout.strip() == "ok"
            and route(lab, "capacity-original"))
        lab.check(
            "positive", "Synthetic NodeIPAM objects are removed and the owned control-plane prefix remains healthy",
            synthetic_absent and prefix_baseline_restored and api_and_marker,
            {"synthetic_nodes_removed": synthetic_absent,
             "control_plane_prefix_baseline_restored": prefix_baseline_restored,
             "api_and_original_marker_healthy": api_and_marker})
