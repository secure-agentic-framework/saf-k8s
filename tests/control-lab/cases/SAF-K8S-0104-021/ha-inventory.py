"""Inspect the exact owned Kind HA endpoint set with authenticated, read-only calls."""

import ipaddress
import json


NODE_IMAGE = ("kindest/node:v1.36.1@sha256:"
              "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5")


def prepare_kind(lab, temporary):
    config = temporary / "kind.yaml"
    config.write_text(
        "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\n"
        "networking:\n  apiServerAddress: 127.0.0.1\n"
        "nodes:\n- role: control-plane\n- role: control-plane\n- role: worker\n"
    )
    return config


def get(lab, *args):
    return json.loads(lab.kubectl("get", *args, "-o", "json").stdout)


def inspect_endpoint(lab, node, version_parser):
    name = node["metadata"]["name"]
    label = lab.command(
        "docker", "exec", name, "hostname",
    ).stdout.strip()
    actual_cluster = lab.command(
        "docker", "inspect", "--format", '{{index .Config.Labels "io.x-k8s.kind.cluster"}}', name,
    ).stdout.strip()
    if label != name or actual_cluster != lab.cluster:
        lab.block("API endpoint node is outside the owned fixture")
    address, = (entry["address"] for entry in node["status"]["addresses"] if entry["type"] == "InternalIP")
    internal = ipaddress.ip_address(address)
    if internal.version != 4 or not internal.is_private:
        lab.block("The owned Kind API server requires a private IPv4 endpoint")
    server = f"https://{internal}:6443"
    data = lab.command(
        "docker", "exec", name, "kubectl", "--kubeconfig=/etc/kubernetes/admin.conf",
        "--server", server, "--request-timeout=12s", "get", "--raw=/version", timeout=18,
    ).stdout
    return version_parser(json.loads(data)["gitVersion"])


def evaluate_inventory(inventory, expected_endpoints, evaluator, policy):
    observed_ids = {server["id"] for server in inventory["api_servers"]}
    if observed_ids != expected_endpoints:
        return {"status": "unverified", "missing": len(expected_endpoints - observed_ids)}
    if evaluator(inventory, policy):
        return {"status": "violation", "missing": 0}
    return {"status": "matched", "missing": 0}


def run(lab, baseline, policy):
    all_nodes = get(lab, "nodes")["items"]
    controllers = {node["metadata"]["name"]: node for node in all_nodes
                   if "node-role.kubernetes.io/control-plane" in node["metadata"]["labels"]}
    expected = {f"{lab.cluster}-control-plane", f"{lab.cluster}-control-plane2"}
    if set(controllers) != expected or len(all_nodes) != 3:
        lab.block("Expected two owned control-plane backends and one worker")
    apis = [{"id": name, "version": inspect_endpoint(lab, controllers[name], baseline._version)}
            for name in sorted(expected)]
    client = baseline._version(json.loads(lab.kubectl("version", "-o", "json").stdout)["clientVersion"]["gitVersion"])
    inventory = {
        "api_servers": apis,
        "kubelets": [{"id": node["metadata"]["name"], "api_servers": sorted(expected),
                      "version": baseline._version(node["status"]["nodeInfo"]["kubeletVersion"])}
                     for node in all_nodes],
        "kubectl_clients": [{"id": "admin", "version": client, "api_servers": sorted(expected)}],
        "kube_proxies": [],
        "kube_controller_managers": [],
        "kube_schedulers": [],
    }
    for pod in get(lab, "pods", "-n", "kube-system")["items"]:
        for container in pod["spec"]["containers"]:
            groups = {"kube-proxy": "kube_proxies", "kube-controller-manager": "kube_controller_managers",
                      "kube-scheduler": "kube_schedulers"}
            component = container["name"]
            if component not in groups:
                continue
            node = pod["spec"]["nodeName"]
            # For the tested upstream minor, the conservative set of both backends covers
            # every proxy and controller even if a component is configured for one endpoint.
            inventory[groups[component]].append({
                "id": pod["metadata"]["name"], "version": baseline._image_version(container),
                "api_servers": sorted(expected), "kubelet": node,
            })
    counts = {key: len(inventory[key]) for key in (
        "api_servers", "kubelets", "kube_proxies", "kube_controller_managers", "kube_schedulers",
    )}
    lab.check("positive", "Both owned control-plane APIs report their versions independently",
              counts == {"api_servers": 2, "kubelets": 3, "kube_proxies": 3,
                         "kube_controller_managers": 2, "kube_schedulers": 2}
              and {entry["version"] for entry in apis} == {"1.36.1"},
              {"instances": counts, "api_versions": sorted(e["version"] for e in apis),
               "owned_https_direct_probes": len(apis)})
    evaluator = baseline.evaluator.evaluate
    complete = evaluate_inventory(inventory, expected, evaluator, policy)
    incomplete = evaluate_inventory({**inventory, "api_servers": apis[:1]}, expected, evaluator, policy)
    lab.check("red", "Removing a known backend observation leaves the inventory unverified",
              incomplete == {"status": "unverified", "missing": 1}, incomplete)
    lab.check("green", "The complete live inventory satisfies every conservatively modeled API relationship",
              complete == {"status": "matched", "missing": 0}, complete)
