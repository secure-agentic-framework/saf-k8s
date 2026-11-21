"""Compare API-server admission startup identity and a harmless LimitRanger probe."""
import copy
from contextlib import contextmanager
import json
from pathlib import Path
import re
import tempfile


NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
NAMESPACE = "saf-admission-probe"
TIMEOUT = 45
PROFILE = json.loads(Path(__file__).with_name("fixtures.json").read_text())
SCOPE = (
    "A local Kubernetes v1.36.1 kind API server only. Compare the runtime startup-"
    "reported native admission plugin names and API-server command/config identity "
    "against a versioned synthetic approved profile, inventory served API-based "
    "webhook/policy objects, and compare the same harmless server-side dry-run Pod "
    "request with only LimitRanger disabled in a disposable before cluster. The "
    "profile is illustrative and does not evidence organizational approval, "
    "production configuration, or managed-service scope."
)


def parse_flags(command, name):
    values = []
    for index, arg in enumerate(command):
        if arg == name:
            values.append(command[index + 1] if index + 1 < len(command) else None)
        elif arg.startswith(name + "="):
            values.append(arg.split("=", 1)[1])
    return values


def csv_flags(command, name):
    values = parse_flags(command, name)
    if any(value is None for value in values):
        return None
    return {item.strip() for value in values for item in value.split(",") if item.strip()}


def server_command(lab, cluster, kubeconfig=None):
    args = ["kubectl"]
    if kubeconfig is None:
        args.extend(["--kubeconfig", str(lab.kubeconfig)])
    else:
        args.extend(["--kubeconfig", str(kubeconfig)])
    args.extend([
        "--context", f"kind-{cluster}", "-n", "kube-system",
        "get", f"pod/kube-apiserver-{cluster}-control-plane", "-o", "json",
    ])
    result = lab.command(*args, timeout=TIMEOUT)
    pod = json.loads(result.stdout)
    containers = [row for row in pod["spec"]["containers"]
                  if row.get("name") == "kube-apiserver"]
    if len(containers) != 1:
        lab.block(f"Could not identify one kube-apiserver container for {cluster}")
    container = containers[0]
    command = container.get("command") or []
    if not command or Path(command[0]).name != "kube-apiserver":
        lab.block(f"Unexpected kube-apiserver command identity for {cluster}")
    return pod, container, command


def kubectl(lab, cluster, kubeconfig, *args, payload=None, allow_failure=False):
    return lab.command(
        "kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}",
        *args, payload=payload, timeout=TIMEOUT, allow_failure=allow_failure,
    )


def effective_native_plugins(lab, cluster, kubeconfig):
    """Parse the API server's own startup-loaded mutating/validating plugin lists."""
    result = kubectl(
        lab, cluster, kubeconfig, "-n", "kube-system", "logs",
        f"pod/kube-apiserver-{cluster}-control-plane", "-c", "kube-apiserver",
    )
    lines = result.stdout.splitlines()
    loaded = {}
    pattern = re.compile(
        r"Loaded\s+(\d+)\s+(mutating|validating) admission controller\(s\) "
        r"successfully in the following order:\s*([A-Za-z0-9, ]+)\.$"
    )
    for line in lines:
        match = pattern.search(line)
        if match:
            count, phase, names = match.groups()
            chain = [name.strip() for name in names.split(",")]
            if len(chain) != int(count) or len(set(chain)) != len(chain):
                lab.block(f"Startup reported an inconsistent {phase} admission chain")
            loaded[phase] = chain
    if set(loaded) != {"mutating", "validating"}:
        lab.block(f"Startup log for {cluster} did not report both admission phases")
    return set(loaded["mutating"]) | set(loaded["validating"]), loaded


def inventory_custom_policy_objects(lab, cluster, kubeconfig):
    """List API-based admission extensions where their APIs are served."""
    kinds = (
        ("mutatingwebhookconfigurations", "admissionregistration.k8s.io"),
        ("validatingwebhookconfigurations", "admissionregistration.k8s.io"),
        ("validatingadmissionpolicies", "admissionregistration.k8s.io"),
        ("validatingadmissionpolicybindings", "admissionregistration.k8s.io"),
        ("mutatingadmissionpolicies", "admissionregistration.k8s.io"),
        ("mutatingadmissionpolicybindings", "admissionregistration.k8s.io"),
    )
    inventory = {}
    discovery = kubectl(lab, cluster, kubeconfig, "api-resources",
                        "--api-group", "admissionregistration.k8s.io", "-o", "name")
    names = set(discovery.stdout.split())
    for resource, group in kinds:
        canonical = f"{resource}.{group}"
        if canonical not in names:
            inventory[resource] = {"served": False, "items": []}
            continue
        result = kubectl(lab, cluster, kubeconfig, "get", canonical, "-o", "name")
        inventory[resource] = {
            "served": True,
            "items": sorted(result.stdout.split()),
        }
    return inventory


def check_profile(lab, cluster, kubeconfig, expected_disabled=frozenset()):
    profile = PROFILE["profile"]
    _, container, command = server_command(lab, cluster, kubeconfig)
    image = container.get("image", "")
    runtime_version = image.rsplit(":", 1)[-1].removeprefix("v")
    live_version = json.loads(kubectl(lab, cluster, kubeconfig, "get", "--raw", "/version").stdout)
    if (runtime_version != profile["kubernetes_version"].removeprefix("v")
            or live_version.get("gitVersion") != profile["kubernetes_version"]):
        lab.block(f"kube-apiserver image is not {profile['kubernetes_version']}: {image}")
    legacy = parse_flags(command, "--admission-control")
    if legacy:
        lab.block("Legacy --admission-control makes the effective plugin set ambiguous")
    config_paths = parse_flags(command, "--admission-control-config-file")
    config_identity = "not-configured" if not config_paths else "configured"
    lab.check(
        "positive",
        f"Runtime Pod command/image identifies kube-apiserver {profile['kubernetes_version']} and no uninspected admission config file",
        config_identity == profile["admission_configuration_file"],
        {"image": image, "admission_control_config_file": config_identity},
    )
    plugins, phases = effective_native_plugins(lab, cluster, kubeconfig)
    enabled = csv_flags(command, "--enable-admission-plugins")
    disabled = csv_flags(command, "--disable-admission-plugins")
    if enabled is None or disabled is None:
        lab.block("Malformed admission plugin enable/disable command flags")
    expected_disabled_flags = set(expected_disabled)
    if not plugins <= set(profile["allowed_native_plugins"]):
        lab.block(f"Runtime native plugin names exceed synthetic profile: {sorted(plugins - set(profile['allowed_native_plugins']))}")
    required = set(profile["required_native_plugins"]) - set(expected_disabled)
    matched = (
        required <= plugins
        and set(expected_disabled).isdisjoint(plugins)
        and disabled == expected_disabled_flags
    )
    lab.check(
        "green" if not expected_disabled else "red",
        f"Startup-loaded native plugins match {profile['id']} required/disabled names",
        matched,
        {"profile": profile["id"], "plugins": sorted(plugins),
         "mutating": phases["mutating"], "validating": phases["validating"],
         "enable_flags": sorted(enabled), "disable_flags": sorted(disabled)},
    )
    inventory = inventory_custom_policy_objects(lab, cluster, kubeconfig)
    served_items = {name: row["items"] for name, row in inventory.items() if row["served"]}
    empty = all(not names for names in served_items.values())
    lab.check(
        "positive",
        "Served API-based webhook/policy configuration objects are inventoried and empty in this synthetic profile",
        empty,
        inventory,
    )
    return phases


def kind_config():
    return (
        "kind: Cluster\n"
        "apiVersion: kind.x-k8s.io/v1alpha4\n"
        "kubeadmConfigPatches:\n"
        "  - |\n"
        "    apiVersion: kubeadm.k8s.io/v1beta4\n"
        "    kind: ClusterConfiguration\n"
        "    apiServer:\n"
        "      extraArgs:\n"
        "        - name: disable-admission-plugins\n"
        "          value: LimitRanger\n"
    )


@contextmanager
def disabled_profile(lab):
    cluster = f"{lab.cluster}-lr-off"
    if cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block(f"Case-owned cluster name already exists: {cluster}")
    with tempfile.TemporaryDirectory(prefix="saf-admission-") as temp:
        kubeconfig = Path(temp) / "kubeconfig"
        config = Path(temp) / "kind.yaml"
        config.write_text(kind_config())
        attempted = False
        try:
            attempted = True
            lab.command(
                "kind", "create", "cluster", "--name", cluster, "--image", NODE_IMAGE,
                "--config", str(config), "--kubeconfig", str(kubeconfig), "--wait", "90s",
                timeout=480,
            )
            kubectl(lab, cluster, kubeconfig, "create", "namespace", NAMESPACE)
            yield cluster, kubeconfig
        finally:
            if attempted:
                result = lab.command(
                    "kind", "delete", "cluster", "--name", cluster,
                    "--kubeconfig", str(kubeconfig), timeout=90, allow_failure=True,
                )
                if result.returncode:
                    lab.block(f"Could not confirm cleanup of case-owned cluster {cluster}")


def apply_limit_range(lab, cluster, kubeconfig):
    manifest = copy.deepcopy(PROFILE["limit_range"])
    manifest["metadata"]["namespace"] = NAMESPACE
    kubectl(lab, cluster, kubeconfig, "apply", "-f", "-", payload=json.dumps(manifest))


def probe(lab, cluster, kubeconfig, resource, expect_allowed, phase, description):
    pod = copy.deepcopy(resource)
    pod["metadata"]["namespace"] = NAMESPACE
    result = kubectl(
        lab, cluster, kubeconfig, "create", "-f", "-", "--dry-run=server", "-o", "json",
        payload=json.dumps(pod), allow_failure=True,
    )
    if expect_allowed:
        condition = result.returncode == 0
        observed = {"returncode": result.returncode, "accepted": condition,
                    "object_created": False, "stderr": result.stderr.strip()}
    else:
        text = result.stderr
        condition = (result.returncode != 0 and "(Forbidden)" in text
                     and "maximum" in text.lower() and "cpu" in text.lower())
        observed = {"returncode": result.returncode, "accepted": False,
                    "forbidden": "(Forbidden)" in text, "message": text.strip(),
                    "object_created": False}
    lab.check(phase, description, condition, observed)


def run(lab):
    # Before: same namespace policy and exact oversized dry-run, with one plugin disabled.
    with disabled_profile(lab) as (cluster, kubeconfig):
        before = check_profile(lab, cluster, kubeconfig, expected_disabled={"LimitRanger"})
        apply_limit_range(lab, cluster, kubeconfig)
        probe(
            lab, cluster, kubeconfig, PROFILE["oversized_pod"], True, "red",
            "With only LimitRanger disabled, the namespace-bounded oversized request reaches admission and is accepted by the server-side dry-run",
        )

    # After: runner-owned default profile; verify identity before applying the same policy/request.
    after = check_profile(lab, lab.cluster, lab.kubeconfig)
    minus_limit_ranger = {
        phase: [name for name in chain if name != "LimitRanger"]
        for phase, chain in after.items()
    }
    lab.check("green", "The comparison changes only LimitRanger in the runtime admission order",
              before == minus_limit_ranger, {"before": before, "after": after})
    kubectl(lab, lab.cluster, lab.kubeconfig, "create", "namespace", NAMESPACE)
    apply_limit_range(lab, lab.cluster, lab.kubeconfig)
    probe(
        lab, lab.cluster, lab.kubeconfig, PROFILE["oversized_pod"], False, "green",
        "With the approved-profile LimitRanger loaded, the identical oversized request is denied at admission",
    )
    probe(
        lab, lab.cluster, lab.kubeconfig, PROFILE["valid_pod"], True, "positive",
        "A bounded benign workload remains permitted by server-side dry-run",
    )
