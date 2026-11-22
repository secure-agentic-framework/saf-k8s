"""Correlate real host-local Pod leases with an exercised capacity alert."""
import ipaddress
import json
import re
import time


POD_CIDR = ipaddress.ip_network("10.244.250.0/28")
ALERT = "KubernetesKindPodIPPoolLow"
METRIC = "saf_lab_kind_pod_ipam_available"
FIXTURES = ("ipam-fixture-a", "ipam-fixture-b", "ipam-fixture-extra")


def wait(lab, read, accept, description):
    deadline = time.monotonic() + 30
    latest = None
    while time.monotonic() < deadline:
        latest = read()
        if accept(latest):
            return latest
        time.sleep(0.4)
    lab.block(f"Timed out waiting for {description}; last observation: {latest}")


def verify(lab, query, monitor, image):
    node = f"{lab.cluster}-control-plane"
    live_node = json.loads(lab.kubectl("get", "node", node, "-o", "json").stdout)
    if live_node["spec"]["podCIDR"] != str(POD_CIDR):
        lab.block("The owned node did not receive the pinned PodCIDR")

    def node_command(*args):
        return lab.command("docker", "exec", node, *args).stdout

    config_paths = node_command("find", "/etc/cni/net.d", "-maxdepth", "1", "-type", "f",
                                "-name", "*kindnet*").splitlines()
    if len(config_paths) != 1 or not re.fullmatch(r"/etc/cni/net.d/[a-zA-Z0-9._-]+", config_paths[0]):
        lab.block("Expected one safe kindnet CNI config path on the owned node")
    config = json.loads(node_command("cat", config_paths[0]))
    ipam, = (plugin["ipam"] for plugin in config["plugins"]
             if plugin.get("ipam", {}).get("type") == "host-local")
    if ipam["dataDir"] != "/run/cni-ipam-state" or config["name"] != "kindnet":
        lab.block("The fixture assumes the pinned kindnet host-local state layout")
    alloc_range, = ipam["ranges"]
    scope, = alloc_range
    if scope["subnet"] != str(POD_CIDR) or "rangeStart" in scope or "rangeEnd" in scope:
        lab.block("The measured Pod CIDR does not match the expected default host-local range")
    gateway = ipaddress.ip_address(scope.get("gateway", str(next(POD_CIDR.hosts()))))
    candidates = set(POD_CIDR.hosts()) - {gateway}
    inspect = lab.command("docker", "inspect", "--format",
                          '{{(index .NetworkSettings.Networks "kind").IPAddress}}', node)
    underlay = ipaddress.ip_address(inspect.stdout.strip())

    def leases():
        names = node_command("ls", "-1", "/run/cni-ipam-state/kindnet").splitlines()
        return {ipaddress.ip_address(name) for name in names if re.fullmatch(r"[0-9.]+", name)} & candidates

    def observe(addresses, firing):
        free = len(candidates - addresses)
        lab.kubectl("exec", "-i", monitor, "-c", "pod-ipam-exporter", "--", "sh", "-c",
                    "cat >/samples/next && mv /samples/next /samples/metrics",
                    payload=f'{METRIC}{{cidr="{POD_CIDR}"}} {free}\n')
        selector = f'cidr="{POD_CIDR}"'
        rule = f'ALERTS{{alertname="{ALERT}",alertstate="firing",{selector}}}'
        measured, active = wait(lab, lambda: (query(lab, f"{METRIC}{{{selector}}}"), query(lab, rule)),
                                lambda pair: pair == ([float(free)], [1.0] if firing else []),
                                "Prometheus to confirm the current Pod IP sample and alert state")
        return {"allocated": len(addresses), "available": int(measured[0]), "alert_firing": bool(active)}

    def add(name):
        resource = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
                    "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                             "terminationGracePeriodSeconds": 1,
                             "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                 "seccompProfile": {"type": "RuntimeDefault"}},
                             "containers": [{"name": "inert", "image": image, "command": ["sleep", "300"],
                                             "securityContext": {"readOnlyRootFilesystem": True,
                                                                 "allowPrivilegeEscalation": False,
                                                                 "capabilities": {"drop": ["ALL"]}}}]}}
        lab.create(resource)
        lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=45s", timeout=52)
        current = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
        return ipaddress.ip_address(current["status"]["podIP"])

    baseline = leases()
    if len(candidates - baseline) not in (9, 10):
        lab.block("The isolated starting capacity differs from the expected fixture range")
    initial = observe(baseline, False)
    first_addresses = {add(name) for name in FIXTURES[:2]}
    if len(first_addresses) != 2 or first_addresses & baseline or not first_addresses <= candidates:
        lab.block("The fixture Pods did not receive distinct new allocator addresses")
    added = wait(lab, leases, lambda addresses: addresses == baseline | first_addresses,
                 "the runtime leases to match both additional Ready Pod addresses")
    warning = observe(added, True)
    lab.check("red", "Live Prometheus fires on the owned Pod CIDR while addresses remain",
              0 < warning["available"] < 9 and warning["alert_firing"],
              {"two_new_runtime_leases_matched_ready_pods": True, "addresses_still_available": True,
               "alert_firing": warning["alert_firing"]})
    extra_address = add(FIXTURES[2])
    if extra_address in added or extra_address not in candidates:
        lab.block("The third fixture Pod did not receive an additional allocator address")
    after_extra = wait(lab, leases, lambda addresses: addresses == added | {extra_address},
                       "the further Ready Pod to have a matching new allocator lease")
    growing = observe(after_extra, True)
    lab.check("positive", "An additional Pod becomes Ready with a new lease while the alert fires",
              growing["alert_firing"] and underlay not in POD_CIDR,
              {"extra_ready_pod_and_allocator_lease_matched": True, "alert_firing": growing["alert_firing"],
               "node_underlay_is_outside_pod_cidr": underlay not in POD_CIDR})

    lab.kubectl("delete", "pod", *FIXTURES, "--wait=true", "--timeout=30s", timeout=36)
    reclaimed = wait(lab, leases, lambda addresses: addresses == baseline, "owned Pod IP leases to be released")
    recovered = observe(reclaimed, False)
    lab.check("green", "Releasing only owned Pod leases clears the warning and restores the original pool",
              recovered == initial and not recovered["alert_firing"],
              {"original_lease_addresses_recovered": reclaimed == baseline,
               "original_capacity_recovered": recovered == initial, "alert_firing": recovered["alert_firing"]})
    evidence = {"allocator": "kindnet host-local", "pod_cidr": str(POD_CIDR), "node_underlay": str(underlay),
                "matched_fixture_pod_and_lease_addresses": sorted(map(str, first_addresses | {extra_address})),
                "warning_threshold_free_addresses": 9, "baseline": initial, "warning": warning,
                "extra_ready": growing, "recovered": recovered}
    (lab.evidence / "pod-ipam-samples.json").write_text(json.dumps(evidence, indent=2) + "\n")
