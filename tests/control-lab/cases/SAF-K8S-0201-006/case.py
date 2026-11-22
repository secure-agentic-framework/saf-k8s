"""Measure the Node Allocatable change from kubelet reservation settings."""
import importlib.util
from pathlib import Path
import tempfile

from lab import NODE_IMAGE


HERE = Path(__file__).parent
SCOPE = (
    "Paired v1.36.1 kind clusters on one local Docker runtime. The baseline uses stock "
    "eviction settings and has no explicit reservations. The reserved arm adds known CPU, "
    "memory and ephemeral storage amounts through systemReserved and kubeReserved and leaves "
    "the other settings alone. The test observes Node Allocatable only. Daemon cgroup "
    "enforcement, workload pressure, capacity sizing and provider behavior remain separate."
)


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
