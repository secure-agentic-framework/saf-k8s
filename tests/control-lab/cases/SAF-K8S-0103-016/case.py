"""Compare loopback and wildcard binding of the real secure component listeners."""
import ipaddress
import json
import re
import subprocess
import tempfile
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
