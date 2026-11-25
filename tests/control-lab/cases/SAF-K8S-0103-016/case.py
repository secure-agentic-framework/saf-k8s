"""Compare loopback and wildcard binding of the real secure component listeners."""
import ipaddress
import json
import re
import secrets
import subprocess
import tempfile
import time
from pathlib import Path


NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
TIMEOUT = 8
HEALTH_PATH = "/healthz"
COMPONENTS = {
    "kube-controller-manager": {"port": 10257, "pod": "kube-controller-manager"},
    "kube-scheduler": {"port": 10259, "pod": "kube-scheduler"},
}
SCOPE = (
    "On isolated disposable kind v1.36.1 Linux nodes, compare controller-manager "
    "and scheduler secure serving bound to 127.0.0.1 with an intentionally broad "
    "0.0.0.0 bind. Read effective arguments and listening sockets, then issue only "
    "HTTPS GET /healthz requests from the owned node over loopback and its own "
    "non-loopback IPv4 address. Responses are discarded; only HTTP status and "
    "connection outcome are retained. No ports are published and no metrics or "
    "profiling routes are requested."
)


def kubectl(lab, cluster, *args):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{cluster}",
        "--request-timeout=3s", *args, timeout=TIMEOUT + 5,
    ).stdout


def component_command(lab, cluster, component):
    pod = f"{COMPONENTS[component]['pod']}-{cluster}-control-plane"
    try:
        row = json.loads(kubectl(lab, cluster, "-n", "kube-system", "get", f"pod/{pod}", "-o", "json"))
        container = next(item for item in row["spec"]["containers"] if item.get("name") == component)
        command = container["command"]
        argv = command + container.get("args", [])
    except (ValueError, KeyError, StopIteration, TypeError):
        lab.block(f"Could not read the {component} mirror Pod command for {cluster}")
    if not command or Path(command[0]).name != component:
        lab.block(f"Unexpected {component} command for {cluster}")
    return argv


def bind_arguments(argv):
    found = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--bind-address":
            found.append(argv[index + 1] if index + 1 < len(argv) else "<missing-value>")
            index += 1
        elif arg.startswith("--bind-address="):
            found.append(arg.split("=", 1)[1])
        index += 1
    return found


def node_ipv4(lab, cluster):
    node = f"{cluster}-control-plane"
    raw = lab.command(
        "docker", "inspect", "--format",
        "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", node,
    ).stdout.split()
    addresses = []
    for value in raw:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.version == 4 and not address.is_loopback and not address.is_unspecified:
            addresses.append(str(address))
    if len(set(addresses)) != 1:
        lab.block(f"Expected one isolated non-loopback IPv4 address for {node}")
    return addresses[0]


def listener_addresses(lab, cluster):
    node = f"{cluster}-control-plane"
    output = lab.command("docker", "exec", node, "ss", "-lntH", timeout=TIMEOUT).stdout
    found = {}
    for component, row in COMPONENTS.items():
        port = str(row["port"])
        matches = []
        for line in output.splitlines():
            fields = line.split()
            if len(fields) < 4:
                continue
            local = fields[3]
            if local.rsplit(":", 1)[-1] == port:
                matches.append(local)
        if len(matches) != 1:
            lab.block(f"Expected one TCP listener for {component} secure port")
        found[component] = matches[0]
    return found


def health_probe(lab, cluster, address, port):
    """Return (status, connected); never capture or retain an HTTP response body."""
    node = f"{cluster}-control-plane"
    url = f"https://{address}:{port}{HEALTH_PATH}"
    result = subprocess.run(
        ["docker", "exec", "--user=65534:65534", node, "/usr/bin/curl",
         "--silent", "--show-error", "--insecure", "--noproxy", "*",
         "--connect-timeout", "2", "--max-time", str(TIMEOUT), "--request", "GET",
         "--output", "/dev/null", "--write-out", "%{http_code}", url],
        env=lab.env, capture_output=True, text=True, timeout=TIMEOUT + 5,
    )
    status = result.stdout.strip()
    if result.returncode == 0 and re.fullmatch(r"[1-5][0-9][0-9]", status):
        return int(status), True
    # curl emits HTTP code 000 on transport failure. Count only an actual
    # connection refusal as the loopback-only outcome, never a TLS, timeout,
    # command, or probe setup failure.
    if result.returncode == 7 and status == "000":
        return None, False
    lab.block("Health probe failed for a reason other than connection refusal")


def check_profile(lab, cluster, mode):
    expected_bind = "127.0.0.1" if mode == "loopback" else "0.0.0.0"
    node_address = node_ipv4(lab, cluster)
    for component in COMPONENTS:
        argv = component_command(lab, cluster, component)
        binds = bind_arguments(argv)
        lab.check(
            "green" if mode == "loopback" else "red",
            f"{component} effective bind-address is exactly {expected_bind}",
            binds == [expected_bind], {"bind_address_arguments": binds},
        )

    listeners = listener_addresses(lab, cluster)
    expected_listener = f"{expected_bind}:"
    for component, local in listeners.items():
        lab.check(
            "green" if mode == "loopback" else "red",
            f"{component} secure port has the expected listening address",
            local.startswith(expected_listener)
            or (mode == "wildcard" and local.rsplit(":", 1)[0] in ("*", "[::]")),
            {"local_listener": local},
        )

    for component, row in COMPONENTS.items():
        local_status, local_connected = health_probe(lab, cluster, "127.0.0.1", row["port"])
        lab.check("positive", f"{component} TLS health check over loopback succeeds in {mode} profile",
                  local_connected and local_status == 200, {"http_status": local_status})

        network_status, network_connected = health_probe(lab, cluster, node_address, row["port"])
        if mode == "wildcard":
            lab.check("red", f"{component} non-loopback node address reaches TLS health listener",
                      network_connected and network_status == 200,
                      {"http_status": network_status, "connected": network_connected})
        else:
            lab.check("green", f"{component} non-loopback node address cannot reach loopback listener",
                      not network_connected,
                      {"http_status": network_status, "connected": network_connected})


def wildcard_config():
    return (
        "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\n"
        "kubeadmConfigPatches:\n  - |\n"
        "    apiVersion: kubeadm.k8s.io/v1beta4\n"
        "    kind: ClusterConfiguration\n"
        "    controllerManager:\n      extraArgs:\n"
        "        - name: bind-address\n          value: 0.0.0.0\n"
        "    scheduler:\n      extraArgs:\n"
        "        - name: bind-address\n          value: 0.0.0.0\n"
    )


def ipv6_config(bind_address):
    quoted = f'"{bind_address}"'
    return (
        "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\n"
        "networking:\n  ipFamily: ipv6\n  apiServerAddress: 127.0.0.1\n"
        "kubeadmConfigPatches:\n  - |\n"
        "    apiVersion: kubeadm.k8s.io/v1beta4\n"
        "    kind: ClusterConfiguration\n"
        "    controllerManager:\n      extraArgs:\n"
        f"        - name: bind-address\n          value: {quoted}\n"
        "    scheduler:\n      extraArgs:\n"
        f"        - name: bind-address\n          value: {quoted}\n"
    )


def ipv6_network(lab, name, network_id, subnet):
    observed = lab.command("docker", "network", "inspect", "--format",
                           "{{.Name}} {{.EnableIPv6}} {{range .IPAM.Config}}{{.Subnet}} {{end}}",
                           network_id, timeout=TIMEOUT).stdout.split()
    if len(observed) < 3:
        lab.block("Disposable Docker bridge has no inspectable address allocations")
    configured = [ipaddress.ip_network(raw, strict=True) for raw in observed[2:]]
    actual = ipaddress.ip_network(subnet, strict=True)
    lab.check("green", "The exact per-run Docker bridge enables the requested IPv6 subnet",
              observed[:2] == [name, "true"] and actual in configured,
              {"ipv6_enabled": observed[1] == "true", "requested_subnet_present": actual in configured})
    return actual


def node_ipv6(lab, cluster, subnet):
    node = f"{cluster}-control-plane"
    raw = lab.command(
        "docker", "inspect", "--format",
    "{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}} {{end}}", node,
    ).stdout.split()
    addresses = []
    for value in raw:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.version == 6 and not address.is_loopback and not address.is_link_local:
            if address in subnet:
                addresses.append(str(address))
    if len(set(addresses)) != 1:
        lab.block("Expected exactly one assigned non-loopback IPv6 address in the owned bridge")
    return addresses[0]


def ipv6_health_probe(lab, cluster, address, port):
    node = f"{cluster}-control-plane"
    url = f"https://[{address}]:{port}{HEALTH_PATH}"
    result = subprocess.run(
        ["docker", "exec", "--user=65534:65534", node, "/usr/bin/curl",
         "--silent", "--show-error", "--insecure", "--noproxy", "*",
         "--connect-timeout", "2", "--max-time", str(TIMEOUT), "--request", "GET",
         "--output", "/dev/null", "--write-out", "%{http_code}", url],
        env=lab.env, capture_output=True, text=True, timeout=TIMEOUT + 5,
    )
    status = result.stdout.strip()
    if result.returncode == 0 and re.fullmatch(r"[1-5][0-9][0-9]", status):
        return int(status), True
    if result.returncode == 7 and status == "000":
        return None, False
    lab.block("IPv6 health probe failed for a reason other than connection refusal")


def set_ipv6_bind(lab, cluster, component):
    node = f"{cluster}-control-plane"
    manifest = f"/etc/kubernetes/manifests/{component}.yaml"
    new_manifest = f"/etc/kubernetes/{component}-saf-ipv6-wildcard.yaml"
    pod = f"pod/{COMPONENTS[component]['pod']}-{cluster}-control-plane"
    before = json.loads(kubectl(lab, cluster, "-n", "kube-system", "get", pod, "-o", "json"))["metadata"]["uid"]
    current = lab.command("docker", "exec", node, "cat", manifest, timeout=TIMEOUT).stdout
    # Quote the wildcard argument because its last colon would otherwise form
    # a YAML mapping key rather than a container command string.
    arguments = r"(?m)^([ \t]*-[ \t]*)[\"']?--bind-address=::1[\"']?[ \t]*$"
    revised, count = re.subn(arguments, lambda m: m[1] + '"--bind-address=::"', current)
    if count != 1:
        lab.block("Expected exactly one loopback bind in the owned static manifest")
    lab.command("docker", "exec", "-i", node, "sh", "-ceu", 'cat >"$2"; mv -- "$2" "$1"',
                "switch-owned-bind", manifest, new_manifest, payload=revised, timeout=TIMEOUT)
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        response = lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{cluster}",
                               "--request-timeout=4s", "-n", "kube-system", "get", pod, "-o", "json",
                               timeout=TIMEOUT + 5, allow_failure=True)
        if response.returncode == 0:
            record = json.loads(response.stdout)
            ready = any(item.get("type") == "Ready" and item.get("status") == "True"
                        for item in record.get("status", {}).get("conditions", []))
            if ready and record["metadata"]["uid"] != before:
                return
        time.sleep(1)
    lab.block(f"Timed out waiting for the owned {component} IPv6 wildcard mirror Pod")


def check_ipv6_profile(lab, cluster, mode, subnet):
    bind, listener = ("::1", "[::1]:") if mode == "loopback" else ("::", "[::]:")
    address = node_ipv6(lab, cluster, subnet)
    for component in COMPONENTS:
        binds = bind_arguments(component_command(lab, cluster, component))
        lab.check("green" if mode == "loopback" else "red",
                  f"IPv6 {component} effective bind-address is exactly {bind}",
                  binds == [bind], {"bind_address_arguments": binds})
    for component, local in listener_addresses(lab, cluster).items():
        lab.check("green" if mode == "loopback" else "red",
                  f"IPv6 {component} secure listener has the expected address",
                  local.startswith(listener) or (mode == "wildcard" and local.startswith("*:")),
                  {"wildcard_or_loopback_listener_observed": True})
    for component, row in COMPONENTS.items():
        local_status, local_connected = ipv6_health_probe(lab, cluster, "::1", row["port"])
        lab.check("positive", f"IPv6 {component} /healthz succeeds on ::1 in {mode} profile",
                  local_connected and local_status == 200, {"http_status": local_status})
        remote_status, remote_connected = ipv6_health_probe(lab, cluster, address, row["port"])
        if mode == "wildcard":
            lab.check("red", f"IPv6 {component} non-loopback address reaches wildcard listener",
                      remote_connected and remote_status == 200,
                      {"http_status": remote_status, "connected": remote_connected})
        else:
            lab.check("green", f"IPv6 {component} non-loopback address cannot reach loopback listener",
                      not remote_connected,
                      {"http_status": remote_status, "connected": remote_connected})


def run_ipv6_profile(lab):
    cluster = f"{lab.cluster}-ipv6-bind"
    network = f"{cluster}-net"
    if cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block("An IPv6 fixture cluster already uses the generated name")
    if lab.command("docker", "network", "inspect", network, allow_failure=True).returncode == 0:
        lab.block("An IPv6 fixture network already uses the generated name")
    original_network = lab.env.get("KIND_EXPERIMENTAL_DOCKER_NETWORK")
    original_kubeconfig = lab.kubeconfig
    subnet = f"fd{secrets.token_hex(1)}:{secrets.token_hex(2)}:{secrets.token_hex(2)}::/64"
    network_id = None
    cluster_attempted = False
    with tempfile.TemporaryDirectory(prefix="saf-k8s-bind-ipv6-") as temp:
        kubeconfig = Path(temp) / "kubeconfig"
        config = Path(temp) / "kind.yaml"
        try:
            created = lab.command("docker", "network", "create", "--driver", "bridge", "--ipv6",
                                  "--subnet", subnet, network, timeout=TIMEOUT)
            network_id = created.stdout.strip()
            if not re.fullmatch(r"[0-9a-f]{64}", network_id):
                network_id = None
                lab.block("Docker did not return the exact identity of the fixture network")
            assigned_subnet = ipv6_network(lab, network, network_id, subnet)
            lab.env["KIND_EXPERIMENTAL_DOCKER_NETWORK"] = network
            config.write_text(ipv6_config("::1"))
            cluster_attempted = True
            lab.command("kind", "create", "cluster", "--name", cluster, "--image", NODE_IMAGE,
                        "--config", str(config), "--kubeconfig", str(kubeconfig), "--wait", "90s", timeout=480)
            lab.kubeconfig = kubeconfig
            check_ipv6_profile(lab, cluster, "loopback", assigned_subnet)
            for component in COMPONENTS:
                set_ipv6_bind(lab, cluster, component)
            check_ipv6_profile(lab, cluster, "wildcard", assigned_subnet)
        finally:
            lab.kubeconfig = original_kubeconfig
            try:
                if cluster_attempted:
                    lab.command("kind", "delete", "cluster", "--name", cluster,
                                "--kubeconfig", str(kubeconfig), timeout=90)
            finally:
                if original_network is None:
                    lab.env.pop("KIND_EXPERIMENTAL_DOCKER_NETWORK", None)
                else:
                    lab.env["KIND_EXPERIMENTAL_DOCKER_NETWORK"] = original_network
                if network_id is not None:
                    lab.command("docker", "network", "rm", network_id, timeout=TIMEOUT)


def run(lab):
    # The runner's case-owned kind.yaml supplies the loopback green profile.
    check_profile(lab, lab.cluster, "loopback")

    cluster = f"{lab.cluster}-bind-red"
    if cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block(f"Additional bind-address profile already exists: {cluster}")
    with tempfile.TemporaryDirectory(prefix="saf-k8s-bind-profile-") as temp:
        kubeconfig = Path(temp) / "kubeconfig"
        config = Path(temp) / "kind.yaml"
        config.write_text(wildcard_config())
        attempted = False
        try:
            attempted = True
            lab.command(
                "kind", "create", "cluster", "--name", cluster, "--image", NODE_IMAGE,
                "--config", str(config), "--kubeconfig", str(kubeconfig), "--wait", "90s",
                timeout=480,
            )
            # The case runner's kubeconfig only names the primary cluster. Use the
            # additional cluster's isolated kubeconfig for mirror Pod inspection.
            original = lab.kubeconfig
            lab.kubeconfig = kubeconfig
            try:
                check_profile(lab, cluster, "wildcard")
            finally:
                lab.kubeconfig = original
        finally:
            if attempted:
                result = lab.command(
                    "kind", "delete", "cluster", "--name", cluster,
                    "--kubeconfig", str(kubeconfig), timeout=90, allow_failure=True,
                )
                if result.returncode:
                    lab.block(f"Could not confirm cleanup of bind-address profile {cluster}")
    run_ipv6_profile(lab)
