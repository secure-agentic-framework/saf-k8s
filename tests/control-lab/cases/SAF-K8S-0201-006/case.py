"""Measure Node Allocatable and native cgroup v2 reservation enforcement."""
import importlib.util
import json
import re
from pathlib import Path
import tempfile
import time

from fixtures import container, pod, ready
from lab import NODE_IMAGE


HERE = Path(__file__).parent
SCOPE = (
    "Paired v1.36.1 kind clusters on one local Docker runtime. The baseline uses stock "
    "eviction settings and has no explicit reservations. The reserved arm adds known CPU, "
    "memory and ephemeral storage amounts through systemReserved and kubeReserved and leaves "
    "the eviction settings alone. The reserved arm also compares two case-owned systemd "
    "slices before and after kubelet enforcement, observes a newly scheduled workload and a "
    "fresh node lease, then restores the baseline configuration. The slices contain only "
    "marker processes. Sizing, daemon placement and load thresholds depend on the deployment."
)


CONFIG = "/var/lib/kubelet/config.yaml"
SLICES = {"system": "safsystem.slice", "kube": "safkube.slice"}
MEMORY_BYTES = {"system": 32 * 1024**2, "kube": 48 * 1024**2}
CPU_WEIGHTS = {"system": 1, "kube": 2}
SETTINGS = {
    "enforceNodeAllocatable": ["pods", "system-reserved", "kube-reserved"],
    "systemReservedCgroup": "/safsystem.slice",
    "kubeReservedCgroup": "/safkube.slice",
}


def configz(lab, node):
    result = lab.kubectl("get", f"--raw=/api/v1/nodes/{node}/proxy/configz",
                         timeout=12, allow_failure=True)
    return None if result.returncode else json.loads(result.stdout)["kubeletconfig"]


def wait_for_config(lab, node, expected):
    deadline = time.monotonic() + 70
    while time.monotonic() < deadline:
        observed = configz(lab, node)
        if observed and all(observed.get(key) == value for key, value in expected.items()):
            return
        time.sleep(1)
    lab.block("The case-owned kubelet did not report the expected reservation configuration")


def write_config(lab, node, text):
    lab.command("docker", "exec", "-i", node, "sh", "-ceu",
                'test -f "$1"; stage=$(mktemp "$1.saf-reservation.XXXXXX"); '
                'trap "rm -f -- \"$stage\"" EXIT; cat > "$stage"; '
                'chmod --reference="$1" "$stage"; mv "$stage" "$1"; '
                'systemctl restart kubelet', "sh", CONFIG, payload=text, timeout=45)


def observe_slice(lab, node, kind):
    name = SLICES[kind]
    unit = f"saf-{kind}-reservation.service"
    result = lab.command(
        "docker", "exec", node, "sh", "-ceu",
        'pid=$(systemctl show --property=MainPID --value "$1"); test "$pid" -gt 0; '
        'cat "/proc/$pid/cgroup" "/sys/fs/cgroup/$2/memory.max" '
        '"/sys/fs/cgroup/$2/cpu.weight" "/sys/fs/cgroup/$2/cpu.max"',
        "sh", unit, name,
    )
    membership, memory, weight, quota = result.stdout.splitlines()
    return {
        "marker_in_slice": membership == f"0::/{name}/{unit}",
        "memory_max": memory,
        "cpu_weight": int(weight),
        "unlimited_cpu_quota": quota.split()[0] == "max",
    }


def lease(lab, node):
    return json.loads(lab.kubectl("-n", "kube-node-lease", "get", "lease", node, "-o", "json").stdout)


def verify_enforcement(lab):
    node = f"{lab.cluster}-control-plane"
    original = lab.command("docker", "exec", node, "cat", CONFIG).stdout
    effective = configz(lab, node)
    if not effective or effective.get("cgroupDriver") != "systemd" or set(
        effective.get("enforceNodeAllocatable", [])
    ) != {"pods"}:
        lab.block("Expected systemd and pods-only enforcement on the owned control plane")
    original_settings = {key: effective.get(key) for key in SETTINGS}
    keys = "|".join(SETTINGS)
    # Remove the existing settings including kubeadm's block sequence, if present.
    changed = re.sub(rf"^(?:{keys}):[^\n]*\n(?:(?:-| +)[^\n]*\n)*", "", original,
                     flags=re.MULTILINE)
    changed += "".join(f"{key}: {json.dumps(value)}\n" for key, value in SETTINGS.items())
    owned_units = []
    try:
        for kind, name in SLICES.items():
            unit = f"saf-{kind}-reservation.service"
            lab.command("docker", "exec", node, "systemd-run", f"--unit={unit}",
                        f"--slice={name}", "--property=Type=exec", "--property=Delegate=yes",
                        "/usr/bin/sleep", "600")
            owned_units.extend((unit, name))
        before = {kind: observe_slice(lab, node, kind) for kind in SLICES}
        lab.check("red", "Allocatable accounting alone leaves the marker cgroups unconstrained",
                  all(item == {"marker_in_slice": True, "memory_max": "max", "cpu_weight": 100,
                               "unlimited_cpu_quota": True} for item in before.values()), before)
        try:
            write_config(lab, node, changed)
            wait_for_config(lab, node, SETTINGS)
            after = {kind: observe_slice(lab, node, kind) for kind in SLICES}
            for kind, item in after.items():
                lab.check("green", f"Kubelet applies native {kind} reservation to its configured marker cgroup",
                          item == {"marker_in_slice": True, "memory_max": str(MEMORY_BYTES[kind]),
                                   "cpu_weight": CPU_WEIGHTS[kind], "unlimited_cpu_quota": True}, item)
            before_lease = lease(lab, node)["spec"]["renewTime"]
            marker = "saf-reservation-marker"
            lab.create(pod(marker, [container("marker", resources={
                "requests": {"cpu": "5m", "memory": "2Mi"},
                "limits": {"cpu": "20m", "memory": "12Mi"},
            })], automountServiceAccountToken=False,
                tolerations=[{"key": "node-role.kubernetes.io/control-plane", "operator": "Exists",
                              "effect": "NoSchedule"}]))
            ready(lab, marker)
            lab.kubectl("wait", "--for=condition=Ready", f"node/{node}", "--timeout=30s")
            renewed = lease(lab, node)
            deadline = time.monotonic() + 25
            while renewed["spec"]["renewTime"] == before_lease and time.monotonic() < deadline:
                time.sleep(1)
                renewed = lease(lab, node)
            node_uid = json.loads(lab.kubectl("get", "node", node, "-o", "json").stdout)["metadata"]["uid"]
            lease_matches = renewed["spec"]["holderIdentity"] == node and any(
                ref["kind"] == "Node" and ref["name"] == node and ref["uid"] == node_uid
                for ref in renewed["metadata"].get("ownerReferences", [])
            )
            new_lease = renewed["spec"]["renewTime"] > before_lease and lease_matches
            live = lab.kubectl("get", "--raw=/readyz").stdout.strip() == "ok"
            lab.check("positive", "Kubelet renews its own lease and starts a new Pod while enforcement is active",
                      new_lease and live, {"node_lease_renewed": new_lease, "pod_ready": True, "api_ready": live})
        finally:
            write_config(lab, node, original)
            wait_for_config(lab, node, original_settings)
    finally:
        if owned_units:
            lab.command("docker", "exec", node, "systemctl", "stop", *owned_units)
    lab.check("positive", "Original effective settings and owned marker slice cleanup are confirmed",
              all(lab.command("docker", "exec", node, "test", "!", "-e", f"/sys/fs/cgroup/{name}",
                              allow_failure=True).returncode == 0 for name in SLICES.values()),
              {"original_reservation_enforcement_restored": True, "marker_slices_removed": True})


def run(lab):
    spec = importlib.util.spec_from_file_location("reservation_quantities", HERE / "verify_observations.py")
    observations = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(observations)
    baseline = f"{lab.cluster}-baseline"
    if baseline in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block("Generated baseline name already exists")
    with tempfile.TemporaryDirectory(prefix="saf-node-reservation-") as temporary:
        directory = Path(temporary)
        config = directory / "baseline.kubeconfig"
        try:
            lab.command("kind", "create", "cluster", "--name", baseline, "--image", NODE_IMAGE,
                        "--kubeconfig", str(config), "--config", str(HERE / "kind-zero.yaml"),
                        "--wait", "90s", timeout=240)
            baseline_capture = lab.command("kubectl", "--kubeconfig", str(config),
                                           "--context", f"kind-{baseline}", "get", "nodes", "-o", "json")
            reserved_capture = lab.kubectl("get", "nodes", "-o", "json")
            baseline_path, reserved_path = directory / "before.json", directory / "after.json"
            baseline_path.write_text(baseline_capture.stdout)
            reserved_path.write_text(reserved_capture.stdout)
            comparison = observations.compare(baseline_path, reserved_path)
            baseline_cpu = comparison["cpu"]["zero_capacity_minus_allocatable"]
            lab.check("red", "Stock kind advertises all measured CPU as allocatable",
                      baseline_cpu == 0, {"cpu_gap_millicores": baseline_cpu})
            for resource, result in comparison.items():
                lab.check("green", f"Reservations reduce advertised {resource} by their exact sum",
                          result["matched"], {"reservation_delta": result["reservation_delta"],
                                              "expected_reservation_delta": result["expected_reservation_delta"]})
        finally:
            lab.command("kind", "delete", "cluster", "--name", baseline, "--kubeconfig", str(config), timeout=90)
    result = lab.kubectl("get", "--raw=/readyz").stdout.strip()
    lab.check("positive", "The reserved cluster stays ready and the baseline cluster was deleted",
              result == "ok" and baseline not in lab.command("kind", "get", "clusters").stdout.splitlines(),
              {"reserved_cluster_ready": result == "ok", "baseline_cleanup": "deleted"})

    verify_enforcement(lab)
