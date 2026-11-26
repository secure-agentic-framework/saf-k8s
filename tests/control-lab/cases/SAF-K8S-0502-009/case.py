"""Measure the real Kubernetes ClusterIP allocation boundary and expansion."""
from ipaddress import ip_address, ip_network
import json
import time
from datetime import datetime, timezone

from fixtures import container, pod, ready

SCOPE = (
    "A single-node local Kind v0.32.0 and Kubernetes v1.36.1 cluster. The "
    "API server allocates addresses in deliberately small IPv4 ServiceCIDRs. "
    "The case reads native ServiceCIDR/IPAddress allocations, reports a "
    "synthetic two-address low-spare threshold, and creates case-owned "
    "events.events.k8s.io/v1 Warning/Normal records from the test harness. "
    "A second ServiceCIDR adds capacity, and both ClusterIP Services serve "
    "the same owned marker through cluster DNS. Node PodCIDR containment is "
    "inspected. The event producer is modeled, not a deployed monitoring "
    "controller. CNI Pod IPAM sizing, node pool exhaustion, dual-stack, "
    "production telemetry, and alert routing require separate evidence."
)
ORIGINAL = ip_network("10.96.0.0/28")
ADDED = ip_network("10.96.1.0/28")
PODS = ip_network("10.244.0.0/16")
MARKER = "saf-0502-009-service-capacity"
LOW_SPARE_THRESHOLD = 2
REPORTER = "saf-0502-009-capacity-fixture"


def service(name):
    return {
        "apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
        "spec": {"type": "ClusterIP", "selector": {"app": "capacity-marker"},
                 "ports": [{"name": "http", "port": 80, "targetPort": 8080}]},
    }


def create_service(lab, name, *, retry_full=False):
    deadline = time.monotonic() + 25
    while True:
        result = lab.create(service(name), allow_failure=True)
        if result.returncode == 0:
            return ip_address(json.loads(result.stdout)["spec"]["clusterIP"]), False
        failure = (result.stderr + result.stdout).lower()
        if "failed to allocate a serviceip" not in failure or "range is full" not in failure:
            lab.block(f"The service allocator returned an unexpected error for {name}")
        if not retry_full or time.monotonic() >= deadline:
            return None, True
        time.sleep(0.4)


def route(lab, name):
    for _ in range(8):
        result = lab.kubectl("exec", "pod/capacity-client", "--", "wget", "-q", "-T", "2",
                             "-O", "-", f"http://{name}/", allow_failure=True)
        if result.returncode == 0 and result.stdout.strip() == MARKER:
            return True
        time.sleep(0.4)
    return False



def pool_snapshot(lab):
    """Read ServiceCIDR and IPAddress API objects and reconcile them to Services."""
    cidr_items = json.loads(lab.kubectl(
        "get", "servicecidrs.networking.k8s.io", "-o", "json").stdout)["items"]
    networks = {}
    for item in cidr_items:
        cidrs = item.get("spec", {}).get("cidrs", [])
        if len(cidrs) != 1:
            lab.block("The fixture expects one IPv4 CIDR per ServiceCIDR object")
        ready_conditions = item.get("status", {}).get("conditions", [])
        if not any(condition.get("type") == "Ready" and condition.get("status") == "True"
                   for condition in ready_conditions):
            lab.block("A declared ServiceCIDR is not Ready for Service allocation")
        network = ip_network(cidrs[0])
        if network.version != 4:
            lab.block("The fixture only evaluates its declared IPv4 pools")
        networks[item["metadata"]["name"]] = network
    if "kubernetes" not in networks or networks["kubernetes"] != ORIGINAL:
        lab.block("The native ServiceCIDR API does not report the expected original pool")
    network_list = list(networks.values())
    for index, network in enumerate(network_list):
        if any(network.overlaps(other) for other in network_list[index + 1:]):
            lab.block("The native ServiceCIDR pools overlap")

    services = json.loads(lab.kubectl("get", "services", "-A", "-o", "json").stdout)["items"]
    service_ips = set()
    service_links = set()
    for item in services:
        spec = item.get("spec", {})
        candidates = spec.get("clusterIPs") or [spec.get("clusterIP")]
        for value in candidates:
            if not value or value == "None":
                continue
            address = ip_address(value)
            if any(address in network for network in networks.values()):
                service_ips.add(address)
                service_links.add((address, item["metadata"].get("namespace", "default"),
                                   item["metadata"]["name"]))

    allocations = json.loads(lab.kubectl(
        "get", "ipaddresses.networking.k8s.io", "-o", "json").stdout)["items"]
    allocated = set()
    allocation_links = set()
    for item in allocations:
        address = ip_address(item["metadata"]["name"])
        if not any(address in network for network in networks.values()):
            continue
        parent = item.get("spec", {}).get("parentRef") or {}
        if parent.get("group", "") != "" or parent.get("resource") != "services" \
                or not parent.get("namespace") or not parent.get("name"):
            lab.block("An in-pool IPAddress does not reference a namespaced core Service")
        allocated.add(address)
        allocation_links.add((address, parent["namespace"], parent["name"]))
    if allocated != service_ips or allocation_links != service_links:
        lab.block("Native IPAddress parent references do not reconcile to in-pool Service ClusterIPs")

    usable = set()
    for network in networks.values():
        usable.update(network.hosts())
    available = usable - allocated
    return {"networks": networks, "usable": usable, "allocated": allocated,
            "service_ips": service_ips, "available": available,
            "allocated_count": len(allocated), "available_count": len(available),
            "cidr_names": sorted(networks)}


def fixture_events(lab):
    items = json.loads(lab.kubectl("get", "events.events.k8s.io", "-o", "json").stdout)["items"]
    return [item for item in items
            if item.get("reportingController") == REPORTER
            and item.get("regarding", {}).get("kind") == "Service"
            and item["regarding"].get("namespace") == "saf-test"
            and item["regarding"].get("name") in {"capacity-original", "capacity-expanded"}]


def emit_capacity_event(lab, *, event_type, reason, state, regarding):
    now = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    event = {
        "apiVersion": "events.k8s.io/v1", "kind": "Event",
        "metadata": {"generateName": "saf-0502-009-capacity-", "namespace": "saf-test"},
        "eventTime": now, "reportingController": REPORTER,
        "reportingInstance": "fixture-capacity-oracle",
        "action": "EvaluateServiceCIDRSpareCapacity", "reason": reason,
        "type": event_type,
        "regarding": {"apiVersion": "v1", "kind": "Service", "namespace": "saf-test",
                      "name": regarding["metadata"]["name"], "uid": regarding["metadata"]["uid"]},
        "note": (f"synthetic fixture observation: allocated={state['allocated_count']}; "
                 f"available={state['available_count']}; "
                 f"threshold={LOW_SPARE_THRESHOLD}; "
                 f"cidrs={','.join(state['cidr_names'])}"),
    }
    return lab.create(event)


def run(lab):
    version = json.loads(lab.kubectl("version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    if version != "v1.36.1":
        lab.block("The cluster is outside the reviewed Kubernetes version")
    cidr = lab.kubectl("get", "servicecidr", "kubernetes",
                       "-o", "jsonpath={.spec.cidrs[0]}").stdout.strip()
    if cidr != str(ORIGINAL):
        lab.block("Kind did not provision the reviewed default service pool")
    node, = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    assigned = ip_network(node["spec"]["podCIDR"])
    lab.check("positive", "The node's allocated PodCIDR stays within the declared Pod subnet",
              assigned.subnet_of(PODS) and not assigned.overlaps(ORIGINAL),
              {"pod_subnet_contains_node_prefix": assigned.subnet_of(PODS),
               "service_pool_disjoint": not assigned.overlaps(ORIGINAL)})

    server = pod("capacity-marker", [container("server", command=[
        "sh", "-ec", f"printf %s {MARKER} >/tmp/index.html; exec httpd -f -p 8080 -h /tmp",
    ])], automountServiceAccountToken=False)
    server["metadata"]["labels"] = {"app": "capacity-marker"}
    lab.create(server)
    lab.create(pod("capacity-client", [container("client")], automountServiceAccountToken=False))
    ready(lab, "capacity-marker")
    ready(lab, "capacity-client")
    original_address, is_full = create_service(lab, "capacity-original")
    if is_full or original_address not in ORIGINAL or not route(lab, "capacity-original"):
        lab.block("The original marker Service could not establish its permitted baseline")
    initial = pool_snapshot(lab)
    allocated = set(initial["allocated"])
    usable = set(ORIGINAL.hosts())
    baseline_available = initial["available_count"]
    if baseline_available <= LOW_SPARE_THRESHOLD:
        lab.block("The fresh fixture does not have enough spare addresses to demonstrate the threshold")
    if initial["usable"] != usable:
        lab.block("The initial native allocator pool differs from the fixture's reviewed range")
    if fixture_events(lab):
        lab.block("A case-owned capacity Event exists before the baseline observation")
    lab.check("positive", "Native ServiceCIDR and IPAddress inventory shows baseline spare capacity above threshold",
              baseline_available > LOW_SPARE_THRESHOLD,
              {"servicecidrs": initial["cidr_names"], "allocated_ipaddresses": initial["allocated_count"],
               "available_ipaddresses": baseline_available, "low_spare_threshold": LOW_SPARE_THRESHOLD,
               "warning_events_at_baseline": 0})

    # Drain only case-owned synthetic Services until the native API reports exactly
    # the low-spare threshold. Emit one explicitly modeled case-owned Warning Event.
    index = 0
    while True:
        before = pool_snapshot(lab)
        if before["available_count"] == LOW_SPARE_THRESHOLD:
            break
        if before["available_count"] < LOW_SPARE_THRESHOLD:
            lab.block("The low-spare threshold was crossed without an observation at the exact boundary")
        address, is_full = create_service(lab, f"capacity-low-spare-{index:02d}")
        if is_full or address not in usable - allocated:
            lab.block("A synthetic Service did not consume one distinct original-pool address")
        allocated.add(address)
        after = pool_snapshot(lab)
        if after["available_count"] != before["available_count"] - 1:
            lab.block("Native IPAddress state did not reflect exactly one Service allocation")
        if after["available_count"] > LOW_SPARE_THRESHOLD and fixture_events(lab):
            lab.block("The case-owned Warning Event appeared before the low-spare threshold")
        index += 1

    warning_state = pool_snapshot(lab)
    if warning_state["available_count"] != LOW_SPARE_THRESHOLD:
        lab.block("The native API no longer reports the exact low-spare threshold")
    original_service = json.loads(lab.kubectl("get", "service", "capacity-original", "-o", "json").stdout)
    warning = emit_capacity_event(lab, event_type="Warning", reason="ServiceCIDRLowSpareAddresses",
                                  state=warning_state, regarding=original_service)
    warning_name = warning["metadata"]["name"]
    observed_warnings = [item for item in fixture_events(lab)
                         if item.get("type") == "Warning"
                         and item.get("reason") == "ServiceCIDRLowSpareAddresses"]
    warning_targets_original = (len(observed_warnings) == 1
                                and observed_warnings[0]["regarding"].get("uid") == original_service["metadata"]["uid"])
    lab.check("positive", "A case-owned Warning Event is recorded at the exact native low-spare threshold",
              warning_state["available_count"] == LOW_SPARE_THRESHOLD
              and len(observed_warnings) == 1
              and observed_warnings[0]["metadata"]["name"] == warning_name
              and warning_targets_original
              and f"available={LOW_SPARE_THRESHOLD};" in observed_warnings[0].get("note", ""),
              {"warning_type": observed_warnings[0]["type"] if observed_warnings else None,
               "warning_reason": observed_warnings[0]["reason"] if observed_warnings else None,
               "allocated_ipaddresses": warning_state["allocated_count"],
               "available_ipaddresses": warning_state["available_count"],
               "warning_event_count": len(observed_warnings),
               "warning_targets_original_service": warning_targets_original,
               "reporter": REPORTER})

    # Preserve the original exhaustion and expansion checks while reading each
    # transition from the actual native allocation objects.
    filled = set()
    for index in range(LOW_SPARE_THRESHOLD):
        before = pool_snapshot(lab)
        address, is_full = create_service(lab, f"capacity-fill-{index:02d}")
        if is_full or address not in usable - allocated:
            lab.block("The service allocator did not consume a distinct expected address")
        filled.add(address)
        allocated.add(address)
        after = pool_snapshot(lab)
        if after["available_count"] != before["available_count"] - 1:
            lab.block("Native IPAddress state did not track a final exhaustion allocation")
    exhausted = pool_snapshot(lab)
    _, is_full = create_service(lab, "capacity-expanded")
    original_still_works = route(lab, "capacity-original")
    lab.check("red", "A new Service is rejected after all usable addresses are allocated",
              is_full and exhausted["available_count"] == 0 and allocated == usable and original_still_works,
              {"all_usable_addresses_allocated": allocated == usable,
               "native_ipaddresses_exhaust_pool": exhausted["available_count"] == 0,
               "range_is_full": is_full, "original_service_still_works": original_still_works})

    lab.create({
        "apiVersion": "networking.k8s.io/v1", "kind": "ServiceCIDR",
        "metadata": {"name": "saf-capacity-extra"}, "spec": {"cidrs": [str(ADDED)]},
    })
    lab.kubectl("wait", "--for=condition=Ready", "servicecidr/saf-capacity-extra", "--timeout=35s")
    expanded_address, is_full = create_service(lab, "capacity-expanded", retry_full=True)
    expanded_service = json.loads(lab.kubectl("get", "service", "capacity-expanded", "-o", "json").stdout)
    lab.check("green", "A second ServiceCIDR permits the previously rejected Service creation",
              not is_full and expanded_address in ADDED,
              {"extra_pool": str(ADDED), "assigned_from_extra_pool": not is_full and expanded_address in ADDED})

    recovered = pool_snapshot(lab)
    recovery_event = emit_capacity_event(
        lab, event_type="Normal", reason="ServiceCIDRCapacityRecovered",
        state=recovered, regarding=expanded_service)
    all_events = fixture_events(lab)
    warnings = [item for item in all_events if item.get("type") == "Warning"
                and item.get("reason") == "ServiceCIDRLowSpareAddresses"]
    recoveries = [item for item in all_events if item.get("type") == "Normal"
                  and item.get("reason") == "ServiceCIDRCapacityRecovered"]
    recovery_targets_expanded = (len(recoveries) == 1
                                 and recoveries[0]["regarding"].get("uid") == expanded_service["metadata"]["uid"])
    recovery_reports_pools = (len(recoveries) == 1
                              and recoveries[0].get("note", "").endswith(f"cidrs={','.join(recovered['cidr_names'])}"))
    lab.check("green", "Native allocation inventory recovers above threshold with a case-owned Normal Event",
              expanded_address in recovered["allocated"]
              and recovered["available_count"] > LOW_SPARE_THRESHOLD
              and len(warnings) == 1 and warnings[0]["metadata"]["name"] == warning_name
              and len(recoveries) == 1
              and recovery_targets_expanded and recovery_reports_pools
              and recoveries[0]["metadata"]["name"] == recovery_event["metadata"]["name"],
              {"servicecidrs": recovered["cidr_names"],
               "allocated_ipaddresses": recovered["allocated_count"],
               "available_ipaddresses": recovered["available_count"],
               "threshold": LOW_SPARE_THRESHOLD,
               "recovery_targets_expanded_service": recovery_targets_expanded,
               "recovery_reports_native_pools": recovery_reports_pools,
               "warning_event_preserved": len(warnings) == 1,
               "normal_recovery_event_count": len(recoveries)})
    original_works = route(lab, "capacity-original")
    expanded_works = route(lab, "capacity-expanded")
    lab.check("positive", "Both original and expanded ClusterIP Services return the marker through DNS",
              original_works and expanded_works,
              {"original_service_route": original_works, "expanded_service_route": expanded_works})
