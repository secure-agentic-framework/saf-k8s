"""Compare controller-manager and scheduler pprof index status on case-owned nodes."""
from contextlib import contextmanager
import base64
import json
import re
import subprocess
import os
from pathlib import Path
import subprocess
import tempfile


NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
TIMEOUT = 8
PPROF_INDEX = "/debug/pprof/"
HEALTH_PATH = "/healthz"
COMPONENTS = {
    "kube-controller-manager": {"port": 10257, "pod": "kube-controller-manager"},
    "kube-scheduler": {"port": 10259, "pod": "kube-scheduler"},
}
ALLOWED_PATHS = frozenset((PPROF_INDEX, HEALTH_PATH))
SCOPE = (
    "Kube-controller-manager and kube-scheduler HTTP profiling index and health on "
    "the loopback listeners of disposable kind nodes. Verify default presence, "
    "both flags disabled, and scheduler enableProfiling=false taking precedence "
    "over its command-line flag. A temporary scoped kubeconfig identity supplies "
    "a bearer token; only HTTP status is recorded."
)
NAMESPACE = "saf-profiling-client"
CONFIG_PATH = "/etc/kubernetes/saf-scheduler-configuration.yaml"
SCHEDULER_CONFIG = """apiVersion: kubescheduler.config.k8s.io/v1
kind: KubeSchedulerConfiguration
clientConnection:
  kubeconfig: /etc/kubernetes/scheduler.conf
leaderElection:
  leaderElect: true
enableProfiling: false
enableContentionProfiling: false
"""


def kubectl(lab, kubeconfig, cluster, *args):
    result = lab.command(
        "kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}",
        "--request-timeout=3s", *args, timeout=TIMEOUT + 5,
    )
    return result.stdout


def component_command(lab, kubeconfig, cluster, component):
    """Read the effective command vector from the exact component mirror Pod."""
    pod = f"{COMPONENTS[component]['pod']}-{cluster}-control-plane"
    try:
        row = json.loads(kubectl(lab, kubeconfig, cluster, "-n", "kube-system",
                                 "get", f"pod/{pod}", "-o", "json"))
        containers = row["spec"]["containers"]
        matches = [container for container in containers if container.get("name") == component]
        command = matches[0]["command"]
        argv = command + matches[0].get("args", [])
    except (ValueError, KeyError, IndexError, TypeError):
        lab.block(f"Could not read the {component} mirror Pod command for {cluster}")
    if not command or Path(command[0]).name != component:
        lab.block(f"Unexpected {component} command for {cluster}")
    return argv


def profiling_arguments(command):
    """Return every spelling of the profiling argument; ambiguity fails closed."""
    found = []
    index = 0
    while index < len(command):
        arg = command[index]
        if arg == "--profiling":
            found.append(command[index + 1] if index + 1 < len(command) else "<missing-value>")
            index += 1
        elif arg.startswith("--profiling="):
            found.append(arg.split("=", 1)[1])
        index += 1
    return found


@contextmanager
def component_identity(lab, cluster, component):
    """Materialize the component's own mTLS identity without logging credentials."""
    node = f"{cluster}-control-plane"
    config_name = "controller-manager.conf" if component == "kube-controller-manager" else "scheduler.conf"
    with tempfile.TemporaryDirectory(prefix="saf-component-client-",
                                     dir=Path(__file__).parent) as temp:
        config_path = Path(temp) / "component.conf"
        lab.command("docker", "cp", f"{node}:/etc/kubernetes/{config_name}", str(config_path),
                    timeout=TIMEOUT + 5)
        # The raw kubeconfig contains a private key. Keep it out of Lab.command's
        # command log and expose only decoded client identity files to the probe.
        result = subprocess.run(
            ["kubectl", "config", "view", "--kubeconfig", str(config_path),
             "--raw", "--minify", "-o", "json"],
            env=lab.env, capture_output=True, text=True, timeout=TIMEOUT, check=False,
        )
        if result.returncode:
            lab.block(f"Could not read the local {component} client identity")
        try:
            user = json.loads(result.stdout)["users"][0]["user"]
            cert_data = base64.b64decode(user["client-certificate-data"], validate=True)
            key_data = base64.b64decode(user["client-key-data"], validate=True)
        except (ValueError, KeyError, IndexError, TypeError):
            lab.block(f"Malformed local {component} client identity")
        cert_path = Path(temp) / "client.crt"
        key_path = Path(temp) / "client.key"
        cert_path.write_bytes(cert_data)
        key_path.write_bytes(key_data)
        # The parent directory remains mode 0700; only the isolated client can
        # read these read-only file mounts under its non-root UID.
        os.chmod(cert_path, 0o444)
        os.chmod(key_path, 0o444)
        yield cert_path, key_path


def identity(lab, kubeconfig, cluster):
    kubectl(lab, kubeconfig, cluster, "create", "namespace", NAMESPACE)
    kubectl(lab, kubeconfig, cluster, "-n", NAMESPACE, "create", "serviceaccount", NAMESPACE)
    base = {"apiVersion": "rbac.authorization.k8s.io/v1", "metadata": {"name": NAMESPACE}}
    role = {**base, "kind": "ClusterRole", "rules": [
        {"nonResourceURLs": [PPROF_INDEX, HEALTH_PATH], "verbs": ["get"]}]}
    binding = {**base, "kind": "ClusterRoleBinding", "roleRef": {
        "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": NAMESPACE},
        "subjects": [{"kind": "ServiceAccount", "name": NAMESPACE, "namespace": NAMESPACE}]}
    prefix = ["kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}"]
    for resource in (role, binding):
        lab.command(*prefix, "create", "-f", "-", payload=json.dumps(resource))
    result = subprocess.run(
        prefix + ["-n", NAMESPACE, "create", "token", NAMESPACE, "--duration=10m"],
        env=lab.env, capture_output=True, text=True, timeout=20,
    )
    token = result.stdout.strip()
    if result.returncode or not re.fullmatch(r"[A-Za-z0-9_.-]+", token):
        lab.block("Unable to obtain the case-owned health and index probe identity")
    return token


def node_local_status(lab, cluster, component, path, token=None):
    if component not in COMPONENTS or path not in ALLOWED_PATHS:
        lab.block("Refusing out-of-scope component or HTTP path")
    node = f"{cluster}-control-plane"
    port = COMPONENTS[component]["port"]
    config = f'header = "Authorization: Bearer {token}"\n' if token else ""
    command = ["docker", "exec", "-i", "--user=65534:65534", node, "/usr/bin/curl",
               "--config", "-", "--silent", "--show-error", "--insecure", "--noproxy", "*",
               "--max-time", str(TIMEOUT), "--request", "GET", "--output", "/dev/null",
               "--write-out", "%{http_code}", f"https://127.0.0.1:{port}{path}"]
    result = subprocess.run(command, input=config, env=lab.env, capture_output=True,
                            text=True, timeout=TIMEOUT+5)
    value = result.stdout.strip()
    if result.returncode or not re.fullmatch(r"[1-5][0-9][0-9]", value):
        lab.block(f"Node-local GET {component}{path} did not return an HTTP status")
    return int(value)


def check_profile(lab, kubeconfig, cluster, mode):
    token = identity(lab, kubeconfig, cluster)
    for component in COMPONENTS:
        command = component_command(lab, kubeconfig, cluster, component)
        args = profiling_arguments(command)
        explicit_config = mode == "config" and component == "kube-scheduler"
        expected = 200 if mode == "default" else 404
        phase = "red" if mode == "default" else "green"
        if mode == "default":
            matches = args in ([], ["true"])
            denial = node_local_status(lab, cluster, component, PPROF_INDEX)
            lab.check("positive", f"{component} requires an authorized caller for the profiling index",
                      denial in (401, 403), {"anonymous_http_status": denial})
        elif explicit_config:
            config = lab.command("docker", "exec", f"{cluster}-control-plane", "cat", CONFIG_PATH).stdout
            matches = args == ["true"] and f"--config={CONFIG_PATH}" in command and config == SCHEDULER_CONFIG
        else:
            matches = args == ["false"] and not (
                component == "kube-scheduler" and any(
                    arg == "--config" or arg.startswith("--config=") for arg in command))
        lab.check(phase, f"{component} uses the expected {mode} settings", matches,
                  {"profiling_flags": args, "scheduler_config_profile": explicit_config})
        status = node_local_status(lab, cluster, component, PPROF_INDEX, token)
        lab.check(phase, f"Authorized {component} profiling index returns {expected} in the {mode} profile",
                  status == expected, {"index_http_status": status})
        health = node_local_status(lab, cluster, component, HEALTH_PATH, token)
        lab.check("positive", f"Authenticated {component} health succeeds in the {mode} profile",
                  health == 200, {"health_http_status": health})


def profile_config(config_file):
    mounts = ""
    config_option = ""
    scheduler_flag = "false"
    if config_file:
        mounts = (
            "nodes:\n  - role: control-plane\n    extraMounts:\n"
            f"      - hostPath: {json.dumps(str(config_file))}\n"
            f"        containerPath: {CONFIG_PATH}\n        readOnly: true\n"
        )
        config_option = (
            f"        - name: config\n          value: {CONFIG_PATH}\n"
            "      extraVolumes:\n        - name: saf-scheduler-config\n"
            f"          hostPath: {CONFIG_PATH}\n          mountPath: {CONFIG_PATH}\n"
            "          readOnly: true\n          pathType: File\n"
        )
        scheduler_flag = "true"
    return (
        "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\n" + mounts +
        "kubeadmConfigPatches:\n  - |\n    apiVersion: kubeadm.k8s.io/v1beta4\n"
        "    kind: ClusterConfiguration\n    controllerManager:\n      extraArgs:\n"
        "        - name: profiling\n          value: \"false\"\n"
        "    scheduler:\n      extraArgs:\n"
        f"        - name: profiling\n          value: \"{scheduler_flag}\"\n" + config_option
    )


@contextmanager
def profiling_disabled_profile(lab, mode):
    cluster = f"{lab.cluster}-pprof-{mode}"
    if cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block(f"Additional profiling profile already exists: {cluster}")
    with tempfile.TemporaryDirectory(prefix="saf-cm-scheduler-pprof-") as temp:
        kubeconfig = Path(temp) / "kubeconfig"
        config = Path(temp) / "kind.yaml"
        component_config = None
        if mode == "config":
            component_config = Path(temp) / "scheduler.yaml"
            component_config.write_text(SCHEDULER_CONFIG)
        config.write_text(profile_config(component_config))
        attempted = False
        try:
            attempted = True
            lab.command(
                "kind", "create", "cluster", "--name", cluster, "--image", NODE_IMAGE,
                "--config", str(config), "--kubeconfig", str(kubeconfig),
                "--wait", "90s", timeout=480,
            )
            yield cluster, kubeconfig
        finally:
            if attempted:
                result = lab.command(
                    "kind", "delete", "cluster", "--name", cluster,
                    "--kubeconfig", str(kubeconfig), timeout=90, allow_failure=True,
                )
                if result.returncode:
                    lab.block(f"Could not confirm cleanup of profiling profile {cluster}")


def run(lab):
    check_profile(lab, lab.kubeconfig, lab.cluster, "default")
    for mode in ("flag", "config"):
        with profiling_disabled_profile(lab, mode) as (cluster, kubeconfig):
            check_profile(lab, kubeconfig, cluster, mode)
