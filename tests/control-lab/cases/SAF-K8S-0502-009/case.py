"""Measure the real Kubernetes ClusterIP allocation boundary and expansion."""
from ipaddress import ip_address, ip_network
import json
import time

from fixtures import container, pod, ready

SCOPE = (
    "A single-node local Kind v0.32.0 and Kubernetes v1.36.1 cluster. The "
    "API server allocates all remaining addresses in a deliberately small "
    "IPv4 ServiceCIDR. A second ServiceCIDR adds capacity, and the original "
    "and new ClusterIP Services both serve the same owned marker through "
    "cluster DNS. Node PodCIDR containment is inspected. Deployed CNI Pod "
    "IPAM sizing, node pool exhaustion, dual-stack, telemetry, and alerts "
    "require separate evidence."
)
ORIGINAL = ip_network("10.96.0.0/28")
ADDED = ip_network("10.96.1.0/28")
PODS = ip_network("10.244.0.0/16")
MARKER = "saf-0502-009-service-capacity"


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
    old = json.loads(lab.kubectl("get", "services", "-A", "-o", "json").stdout)["items"]
    used = {ip_address(ip) for item in old for ip in item["spec"].get("clusterIPs", []) if ip != "None"}
    usable = set(ORIGINAL.hosts())
    used &= usable
    remaining = len(usable - used)
    if not remaining:
        lab.block("The reviewed pool has no spare fixture capacity at baseline")

    filled = set()
    for index in range(remaining):
        address, is_full = create_service(lab, f"capacity-fill-{index:02d}")
        if is_full or address not in usable - used - filled:
            lab.block("The service allocator did not consume a distinct expected address")
        filled.add(address)
    _, is_full = create_service(lab, "capacity-expanded")
    original_still_works = route(lab, "capacity-original")
    lab.check("red", "A new Service is rejected after all usable addresses are allocated",
              is_full and used | filled == usable and original_still_works,
              {"all_usable_addresses_allocated": used | filled == usable,
               "range_is_full": is_full, "original_service_still_works": original_still_works})

    lab.create({
        "apiVersion": "networking.k8s.io/v1", "kind": "ServiceCIDR",
        "metadata": {"name": "saf-capacity-extra"}, "spec": {"cidrs": [str(ADDED)]},
    })
    lab.kubectl("wait", "--for=condition=Ready", "servicecidr/saf-capacity-extra", "--timeout=35s")
    expanded_address, is_full = create_service(lab, "capacity-expanded", retry_full=True)
    lab.check("green", "A second ServiceCIDR permits the previously rejected Service creation",
              not is_full and expanded_address in ADDED,
              {"extra_pool": str(ADDED), "assigned_from_extra_pool": not is_full and expanded_address in ADDED})
    original_works = route(lab, "capacity-original")
    expanded_works = route(lab, "capacity-expanded")
    lab.check("positive", "Both original and expanded ClusterIP Services return the marker through DNS",
              original_works and expanded_works,
              {"original_service_route": original_works, "expanded_service_route": expanded_works})
