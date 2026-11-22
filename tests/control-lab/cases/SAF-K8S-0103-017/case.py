"""Check legacy serving removal and controlled secure health endpoint exposure."""
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
# Historical insecure serving ports from the Kubernetes component docs/source.
LEGACY_PORTS = {"kube-controller-manager": 10252, "kube-scheduler": 10251}
LEGACY_FLAGS = ("port", "address", "insecure-port")
SCOPE = (
    "On isolated disposable kind v1.36.1 Linux nodes, verify component help and "
    "effective Pod arguments contain no legacy --port, --address, or "
    "--insecure-port options, and no TCP listeners use the historical insecure "
    "ports 10252/10251. Compare secure ports 10257/10259 bound to 127.0.0.1 "
    "against an intentionally broad 0.0.0.0 bind. Probe only the owned node's "
    "fixed /healthz endpoint over HTTPS, discard response bodies, and retain only "
    "status/connectivity and listener metadata. No ports are published and no "
    "metrics, profiling, or other route is requested."
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


def has_flag(argv, name):
    return any(arg == f"--{name}" or arg.startswith(f"--{name}=") for arg in argv)


def component_flags_probe(lab, cluster, component, *flags):
    pod = f"{component}-{cluster}-control-plane"
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{cluster}",
        "-n", "kube-system", "--request-timeout=10s", "exec", f"pod/{pod}",
        "-c", component, "--", component, *flags, "--help",
        allow_failure=True, timeout=20,
    )


def help_flags(lab, cluster, component):
    result = component_flags_probe(lab, cluster, component)
    if result.returncode:
        lab.block(f"Could not read help from the running {component} image")
    help_text = result.stdout + result.stderr

    def documented(name):
        return bool(re.search(rf"(?m)^[ \t]*--{re.escape(name)}(?:[= \t,]|$)", help_text))

    return {name: documented(name) for name in LEGACY_FLAGS}, all(
        documented(name) for name in ("bind-address", "secure-port")
    )


def reject_removed_flags(lab, cluster, component):
    results = {}
    for flag in ("--port=0", "--address=127.0.0.1"):
        output = component_flags_probe(lab, cluster, component, flag)
        name = flag.split("=")[0]
        results[name] = output.returncode != 0 and f"unknown flag: {name}" in (output.stderr + output.stdout)
    lab.check("green", f"{component} parser rejects both removed flags",
              all(results.values()), results)


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


def listeners(lab, cluster):
    output = lab.command(
        "docker", "exec", f"{cluster}-control-plane", "ss", "-lntH", timeout=TIMEOUT,
    ).stdout
    by_port = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 4:
            local = fields[3]
            port = local.rsplit(":", 1)[-1]
            by_port.setdefault(port, []).append(local)
    return by_port


def component_listeners(lab, cluster):
    by_port = listeners(lab, cluster)
    secure = {}
    for component, row in COMPONENTS.items():
        matches = by_port.get(str(row["port"]), [])
        if len(matches) != 1:
            lab.block(f"Expected exactly one secure TCP listener for {component}")
        secure[component] = matches[0]
    legacy = {
        component: by_port.get(str(port), [])
        for component, port in LEGACY_PORTS.items()
    }
    return secure, legacy


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


def health_probe(lab, cluster, address, port):
    """Return status/connectivity only; curl sends the body to /dev/null."""
    node = f"{cluster}-control-plane"
    result = subprocess.run(
        ["docker", "exec", "--user=65534:65534", node, "/usr/bin/curl",
         "--silent", "--show-error", "--insecure", "--noproxy", "*",
         "--connect-timeout", "2", "--max-time", str(TIMEOUT), "--request", "GET",
         "--output", "/dev/null", "--write-out", "%{http_code}",
         f"https://{address}:{port}{HEALTH_PATH}"],
        env=lab.env, capture_output=True, text=True, timeout=TIMEOUT + 5,
    )
    status = result.stdout.strip()
    if result.returncode == 0 and re.fullmatch(r"[1-5][0-9][0-9]", status):
        return int(status), True
    if result.returncode == 7 and status == "000":
        return None, False
    lab.block("Health probe failed for a reason other than connection refusal")


def check_profile(lab, cluster, mode):
    expected_bind = "127.0.0.1" if mode == "loopback" else "0.0.0.0"
    node_address = node_ipv4(lab, cluster)

    for component in COMPONENTS:
        argv = component_command(lab, cluster, component)
        legacy_args = {name: has_flag(argv, name) for name in LEGACY_FLAGS}
        binds = bind_arguments(argv)
        phase = "green" if mode == "loopback" else "red"
        lab.check(phase, f"{component} effective arguments omit legacy serving flags",
                  not any(legacy_args.values()), {"legacy_flags_present": legacy_args})
        lab.check(phase, f"{component} secure bind address is {expected_bind}",
                  binds == [expected_bind], {"bind_address_arguments": binds})

        help_legacy, secure_help = help_flags(lab, cluster, component)
        lab.check("green", f"{component} v1.36.1 help omits deprecated insecure serving flags",
                  not any(help_legacy.values()) and secure_help,
                  {"legacy_flags_present": help_legacy, "secure_flags_present": secure_help})
        if mode == "loopback":
            reject_removed_flags(lab, cluster, component)

    secure, legacy = component_listeners(lab, cluster)
    for component, local in secure.items():
        lab.check("green" if mode == "loopback" else "red",
                  f"{component} secure listener has expected bind address",
                  local.startswith(f"{expected_bind}:")
                  or (mode == "wildcard" and local.rsplit(":", 1)[0] in ("*", "[::]")),
                  {"local_listener": local})
    lab.check("green", "No listener uses either historical insecure component port",
              not any(legacy.values()), {"legacy_port_listeners": legacy})

    for component, row in COMPONENTS.items():
        local_status, local_connected = health_probe(lab, cluster, "127.0.0.1", row["port"])
        lab.check("positive", f"{component} permitted HTTPS /healthz on loopback returns 200",
                  local_connected and local_status == 200, {"http_status": local_status})

        remote_status, remote_connected = health_probe(lab, cluster, node_address, row["port"])
        if mode == "wildcard":
            lab.check("red", f"{component} non-loopback node address reaches secure health listener",
                      remote_connected and remote_status == 200,
                      {"http_status": remote_status, "connected": remote_connected})
        else:
            lab.check("green", f"{component} non-loopback node address cannot reach loopback listener",
                      not remote_connected,
                      {"http_status": remote_status, "connected": remote_connected})


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
    # The runner's case-owned kind.yaml supplies the loopback-only green profile.
    check_profile(lab, lab.cluster, "loopback")

    cluster = f"{lab.cluster}-exposure-red"
    if cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block(f"Additional exposure profile already exists: {cluster}")
    with tempfile.TemporaryDirectory(prefix="saf-k8s-exposure-profile-") as temp:
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
                    lab.block(f"Could not confirm cleanup of exposure profile {cluster}")
