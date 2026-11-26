"""Measure the real Kubernetes ClusterIP allocation boundary and expansion."""
from ipaddress import ip_address, ip_network
import json
import re
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
    "the same owned marker through cluster DNS. A dedicated IPv4 kindnet "
    "host-local /28 Pod range is filled with small owned Pods until one native "
    "sandbox event confirms IPAM exhaustion; freeing one holder restores one "
    "sentinel Pod. Node-prefix exhaustion is not tested. The Service capacity "
    "event producer is modeled, not a deployed monitoring controller. Pod "
    "alerting, production telemetry, and alert routing require separate evidence."
)
ORIGINAL = ip_network("10.96.0.0/28")
ADDED = ip_network("10.96.1.0/28")
PODS = ip_network("10.244.250.0/28")
PODCIDR = ip_network("10.244.250.0/28")
MAX_CASE_OWNED_POD_ATTEMPTS = 13
MARKER = "saf-0502-009-service-capacity"
LOW_SPARE_THRESHOLD = 2
REPORTER = "saf-0502-009-capacity-fixture"


def service(name):
    return {
        "apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
        "spec": {"type": "ClusterIP", "selector": {"app": "capacity-marker"},
                 "ports": [{"name": "http", "port": 80, "targetPort": 8080}]},
    }


def service_for(name, selector):
    resource = service(name)
    resource["spec"]["selector"] = {"app": selector}
    return resource


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


def _ipam_pod(name, *, server=False):
    command = ["sh", "-ec", "sleep 600"]
    labels = {"app": name}
    if server:
        command = ["sh", "-ec",
                   f"printf %s {MARKER} >/tmp/index.html; exec httpd -f -p 8080 -h /tmp"]
    resource = pod(name, [container(
        "inert", command=command,
        resources={"requests": {"cpu": "5m", "memory": "8Mi"},
                   "limits": {"cpu": "25m", "memory": "16Mi"}})],
        automountServiceAccountToken=False, terminationGracePeriodSeconds=1)
    resource["metadata"]["labels"] = labels
    return resource


def _pod_ipam_setup(lab):
    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    if len(nodes) != 1:
        lab.block("Pod-IP exhaustion fixture requires its exact single Kind node")
    node = nodes[0]
    node_name = node["metadata"]["name"]
    if (node_name != f"{lab.cluster}-control-plane"
            or node.get("spec", {}).get("podCIDR") != str(PODCIDR)):
        lab.block("The owned Kind node did not receive the pinned /28 PodCIDR")
    pod_capacity = int(node.get("status", {}).get("capacity", {}).get("pods", "0"))
    if pod_capacity < 1:
        lab.block("Kubelet did not publish a Pod capacity for the owned node")

    def node_command(*args):
        return lab.command("docker", "exec", node_name, *args).stdout

    config_paths = node_command("find", "/etc/cni/net.d", "-maxdepth", "1", "-type", "f",
                                "-name", "*kindnet*").splitlines()
    if len(config_paths) != 1 or not re.fullmatch(
            r"/etc/cni/net.d/[A-Za-z0-9._-]+", config_paths[0]):
        lab.block("Expected exactly one safe kindnet CNI config path on the owned node")
    config = json.loads(node_command("cat", config_paths[0]))
    ipam_configs = [plugin.get("ipam", {}) for plugin in config.get("plugins", [])
                    if plugin.get("ipam", {}).get("type") == "host-local"]
    if (config.get("name") != "kindnet" or len(ipam_configs) != 1
            or ipam_configs[0].get("dataDir") != "/run/cni-ipam-state"):
        lab.block("The pinned kindnet host-local state layout is not present")
    ipam = ipam_configs[0]
    range_sets = ipam.get("ranges", [])
    if len(range_sets) != 1 or len(range_sets[0]) != 1:
        lab.block("The fixture expects one IPv4 host-local range for the node")
    scope = range_sets[0][0]
    if (scope.get("subnet") != str(PODCIDR)
            or "rangeStart" in scope or "rangeEnd" in scope):
        lab.block("The actual kindnet IPAM range differs from the pinned PodCIDR")
    gateway = ip_address(scope.get("gateway", str(next(PODCIDR.hosts()))))
    if gateway != next(PODCIDR.hosts()):
        lab.block("The host-local gateway differs from the reviewed /28 default")
    addresses = set(PODCIDR.hosts()) - {gateway}
    if len(addresses) != 13:
        lab.block("The pinned IPv4 /28 does not expose the expected 13 Pod addresses")

    state_dir = ipam["dataDir"].rstrip("/") + "/" + config["name"]

    def leases():
        names = node_command("ls", "-1", state_dir).splitlines()
        parsed = {ip_address(value) for value in names if re.fullmatch(r"[0-9.]+", value)}
        if not parsed <= addresses:
            lab.block("kindnet host-local state contains an address outside its exact Pod range")
        return parsed

    return node_name, pod_capacity, addresses, leases, node_command


def _bound_nonterminal_pods(lab, node_name):
    items = json.loads(lab.kubectl("get", "pods", "-A", "-o", "json").stdout)["items"]
    return [pod_item for pod_item in items
            if pod_item.get("spec", {}).get("nodeName") == node_name
            and pod_item.get("status", {}).get("phase") not in {"Succeeded", "Failed"}]


def _native_ipam_exhaustion_event(lab, namespace, pod_name, pod_uid):
    items = json.loads(lab.kubectl(
        "get", "events.events.k8s.io", "-A", "-o", "json").stdout)["items"]
    for event in items:
        regarding = event.get("regarding", {})
        if (regarding.get("kind") != "Pod" or regarding.get("namespace") != namespace
                or regarding.get("name") != pod_name or regarding.get("uid") != pod_uid):
            continue
        note = (event.get("note") or event.get("message") or "").lower()
        signature = ("failed to allocate for range" in note
                     and "no ip addresses available in range set" in note)
        if event.get("type") == "Warning" and event.get("reason") == "FailedCreatePodSandBox" \
                and signature:
            return {"warning": True, "reason_matches": True,
                    "event_uid_matches_pod": True, "host_local_exhaustion_signature": True}
    return {"warning": False, "reason_matches": False,
            "event_uid_matches_pod": False, "host_local_exhaustion_signature": False}


def _wait_native_ipam_failure(lab, node_name, pod_name, pod_uid):
    deadline = time.monotonic() + 35
    latest = None
    while time.monotonic() < deadline:
        pod_data = json.loads(lab.kubectl("get", "pod", pod_name, "-o", "json").stdout)
        event_state = _native_ipam_exhaustion_event(
            lab, pod_data["metadata"].get("namespace", "default"), pod_name, pod_uid)
        status = pod_data.get("status", {})
        latest = {
            "scheduled_to_owned_node": pod_data.get("spec", {}).get("nodeName") == node_name,
            "pod_ip_absent": not status.get("podIP"),
            **event_state,
        }
        if (latest["scheduled_to_owned_node"] and latest["pod_ip_absent"]
                and event_state["warning"] and event_state["event_uid_matches_pod"]
                and event_state["host_local_exhaustion_signature"]):
            return pod_data, latest
        time.sleep(0.5)
    return pod_data, latest or {
        "scheduled_to_owned_node": False, "pod_ip_absent": False,
        "warning": False, "reason_matches": False,
        "event_uid_matches_pod": False, "host_local_exhaustion_signature": False,
    }


def _wait_for_leases(lab, read_leases, expected):
    deadline = time.monotonic() + 35
    latest = set()
    while time.monotonic() < deadline:
        latest = read_leases()
        if latest == expected:
            return latest
        time.sleep(0.4)
    return latest


def run_pod_ipam_exhaustion(lab):
    node_name, pod_capacity, addresses, read_leases, _node_command = _pod_ipam_setup(lab)
    baseline_leases = read_leases()
    baseline_pods = _bound_nonterminal_pods(lab, node_name)
    existing_case_pods = ("capacity-marker", "capacity-client")
    existing_case_ips = set()
    existing_case_nodes = set()
    for name in existing_case_pods:
        item = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
        address = item.get("status", {}).get("podIP")
        if not address or ip_address(address) not in baseline_leases:
            lab.block("An existing case Pod IP does not match the kindnet lease inventory")
        existing_case_ips.add(ip_address(address))
        existing_case_nodes.add(item.get("spec", {}).get("nodeName"))
    free_before = len(addresses - baseline_leases)
    starting_pod_count = len(baseline_pods)
    headroom = (node_name and free_before > 0
                and node_name == baseline_pods[0].get("spec", {}).get("nodeName")
                and pod_capacity > starting_pod_count + free_before + 1
                and free_before + len(existing_case_pods) + 2 <= MAX_CASE_OWNED_POD_ATTEMPTS
                and existing_case_ips <= baseline_leases
                and existing_case_nodes == {node_name})
    lab.check(
        "positive", "Actual host-local /28 range and kubelet Pod headroom are bounded",
        headroom,
        {"allocator": "kindnet-host-local", "podcidr_exact": True,
         "host_local_addresses": len(addresses),
         "free_before_test": free_before,
         "kubelet_capacity_exceeds_exhaustion_attempt": pod_capacity > starting_pod_count + free_before + 1,
         "case_owned_attempt_cap_respected": (
             free_before + len(existing_case_pods) + 2 <= MAX_CASE_OWNED_POD_ATTEMPTS),
         "existing_case_pods_match_leases": existing_case_ips <= baseline_leases,
         "existing_case_pods_use_owned_node": existing_case_nodes == {node_name}})
    if not headroom:
        lab.block("The pinned one-node /28 fixture lacks safe IPAM or kubelet headroom")

    holder_names = []
    holder_ips = {}
    failed_name = "saf-0502-009-ipam-exhaustion-probe"
    recovery_name = "saf-0502-009-ipam-recovery-sentinel"
    service_name = "saf-0502-009-ipam-recovery"
    all_test_pods = []
    failed_state = None
    recovery_ok = False
    cleanup_ok = False
    sentinel_marker_ok = False
    try:
        current_leases = set(baseline_leases)
        for index in range(free_before):
            name = f"saf-0502-009-ipam-holder-{index:02d}"
            if len(all_test_pods) + len(existing_case_pods) + 2 > MAX_CASE_OWNED_POD_ATTEMPTS:
                lab.block("Pod IPAM case-owned Pod attempt cap would be exceeded")
            lab.create(_ipam_pod(name))
            all_test_pods.append(name)
            ready(lab, name)
            item = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
            observed_ip = ip_address(item.get("status", {}).get("podIP", "0.0.0.0"))
            next_leases = _wait_for_leases(lab, read_leases, current_leases | {observed_ip})
            if (item.get("spec", {}).get("nodeName") != node_name
                    or observed_ip not in addresses or observed_ip in current_leases
                    or next_leases != current_leases | {observed_ip}):
                lab.block("A ready holder Pod did not consume exactly one new in-range host-local lease")
            holder_names.append(name)
            holder_ips[name] = observed_ip
            current_leases = next_leases

        if current_leases != addresses:
            lab.block("Owned holder Pods did not account for every address in the actual host-local pool")

        lab.create(_ipam_pod(failed_name))
        all_test_pods.append(failed_name)
        failed_pod = json.loads(lab.kubectl("get", "pod", failed_name, "-o", "json").stdout)
        failed_uid = failed_pod["metadata"]["uid"]
        failed_pod, failed_state = _wait_native_ipam_failure(
            lab, node_name, failed_name, failed_uid)
        exhaustion_ok = (
            failed_state["scheduled_to_owned_node"]
            and failed_state["pod_ip_absent"]
            and failed_state["warning"]
            and failed_state["reason_matches"]
            and failed_state["event_uid_matches_pod"]
            and failed_state["host_local_exhaustion_signature"]
            and read_leases() == addresses
        )
        lab.check(
            "red", "Native kubelet event confirms the owned Pod IPAM pool is exhausted",
            exhaustion_ok,
            {"all_host_local_addresses_leased": read_leases() == addresses,
             "failed_pod_scheduled_to_owned_node": failed_state["scheduled_to_owned_node"],
             "failed_pod_has_no_ip": failed_state["pod_ip_absent"],
             "native_warning_reason": "FailedCreatePodSandBox" if failed_state["reason_matches"] else "unmatched",
             "event_regarding_uid_matches_exact_probe": failed_state["event_uid_matches_pod"],
             "sanitized_error_class": (
                 "host-local-no-addresses" if failed_state["host_local_exhaustion_signature"]
                 else "unrecognized")})

        if exhaustion_ok:
            # Stop kubelet retries before returning one address to the pool.
            lab.kubectl("delete", "pod", failed_name, "--wait=true", "--timeout=30s", timeout=36)
            all_test_pods.remove(failed_name)
            release_name = holder_names[-1]
            release_ip = holder_ips[release_name]
            lab.kubectl("delete", "pod", release_name, "--wait=true", "--timeout=30s", timeout=36)
            all_test_pods.remove(release_name)
            holder_names.remove(release_name)
            released_leases = _wait_for_leases(lab, read_leases, addresses - {release_ip})
            if released_leases != addresses - {release_ip}:
                lab.block("Deleting the owned IPAM holder did not return exactly one host-local lease")

            lab.create(_ipam_pod(recovery_name, server=True))
            all_test_pods.append(recovery_name)
            ready(lab, recovery_name)
            recovery_pod = json.loads(lab.kubectl("get", "pod", recovery_name, "-o", "json").stdout)
            recovered_ip = ip_address(recovery_pod.get("status", {}).get("podIP", "0.0.0.0"))
            recovered_leases = _wait_for_leases(lab, read_leases, addresses)
            if recovered_leases != addresses:
                lab.block("The recovery sentinel did not restore exactly one host-local lease")
            lab.create(service_for(service_name, recovery_name))
            sentinel_service = json.loads(lab.kubectl(
                "get", "service", service_name, "-o", "json").stdout)
            service_ip = ip_address(sentinel_service["spec"]["clusterIP"])
            sentinel_marker_ok = route(lab, service_name)
            existing_marker_ok = route(lab, "capacity-original")
            recovery_ok = (
                recovered_ip == release_ip and recovered_ip in addresses
                and recovered_leases == addresses and service_ip in ADDED
                and sentinel_marker_ok and existing_marker_ok
            )
            lab.check(
                "green", "Deleting one holder restores one in-range sentinel Pod and marker service",
                recovery_ok,
                {"one_holder_lease_released": released_leases == addresses - {release_ip},
                 "sentinel_reused_released_in_range_address": (
                     recovered_ip == release_ip and recovered_ip in addresses),
                 "sentinel_service_uses_expanded_service_pool": service_ip in ADDED,
                 "sentinel_returns_case_marker": sentinel_marker_ok,
                 "original_marker_service_still_works": existing_marker_ok})
    finally:
        lab.kubectl("delete", "service", service_name, "--ignore-not-found=true",
                    allow_failure=True)
        if all_test_pods:
            lab.kubectl("delete", "pod", *all_test_pods, "--ignore-not-found=true",
                        "--wait=true", "--timeout=45s", timeout=52, allow_failure=True)
        restored = _wait_for_leases(lab, read_leases, baseline_leases) == baseline_leases
        marker_after_cleanup = route(lab, "capacity-original")
        cleanup_ok = restored and marker_after_cleanup
        lab.check(
            "positive", "Owned Pod IPAM cleanup restores baseline leases and marker connectivity",
            cleanup_ok,
            {"owned_host_local_leases_returned_to_baseline": restored,
             "case_marker_service_still_works": marker_after_cleanup})


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

    # The Pod allocator check shares this exact disposable node. It runs only
    # after the original seven ServiceCIDR assertions have completed.
    run_pod_ipam_exhaustion(lab)
