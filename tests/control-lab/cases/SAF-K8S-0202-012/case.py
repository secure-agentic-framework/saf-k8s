"""Validate rootless node reporting and independently managed Pod eligibility."""

import json
import platform
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory


CASE = Path(__file__).resolve().parent
NODE_IMAGE = "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
VM = "rootless-fixture"
FIELD = "runningInUserNamespace"
SCOPE = (
    "Kubernetes v1.37.0 on rootful Docker kind nodes and a separate rootless Podman "
    "kind node in a mount-free Linux guest on macOS ARM64. Verify effective node/kernel "
    "namespace membership and one scheduler selector with an independently managed label. "
    "The fixture checks a scoped issuer, NodeRestriction, freshness loss and recovery, "
    "and the scheduler's handling of existing workloads. Provider-specific support, "
    "runtime/CNI/CSI combinations and external attestation require adopter evidence."
)

GUEST_LAUNCH = '''set -euo pipefail
cd /tmp
fixture_uid=$(id -u safroot)
sudo -u safroot test -S "/run/user/$fixture_uid/bus"
sudo -Hu safroot env XDG_RUNTIME_DIR="/run/user/$fixture_uid" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$fixture_uid/bus" bash -s
'''


def prepare_kind(_lab, temporary):
    destination = temporary / "kind.yaml"
    shutil.copyfile(CASE / "kind.yaml", destination)
    return destination


def rootful_report(lab):
    node = f"{lab.cluster}-control-plane"
    obj = json.loads(lab.kubectl("get", "node", node, "-o", "json").stdout)
    status = obj["status"]["nodeInfo"]
    pid = lab.command("docker", "exec", node, "systemctl", "show", "kubelet.service",
                      "--property=MainPID", "--value").stdout.strip()
    if not pid.isdecimal() or pid == "0":
        lab.block("The owned rootful node has no running kubelet")
    layout = lab.command("docker", "exec", node, "cat", f"/proc/{pid}/uid_map").stdout.split()
    observed = {
        "version": status["kubeletVersion"],
        "node_signal": status.get(FIELD),
        "kubelet_initial_uid_map": layout == ["0", "0", "4294967295"],
    }
    lab.check("red", "The default-on kubelet gate leaves an ordinary rootful node rootful",
              observed == {"version": "v1.37.0", "node_signal": False, "kubelet_initial_uid_map": True},
              observed)


def absent_status_report(lab):
    worker = f"{lab.cluster}-worker"
    lab.kubectl("wait", "--for=condition=Ready", f"node/{worker}", "--timeout=90s", timeout=105)
    node = json.loads(lab.kubectl("get", "node", worker, "-o", "json").stdout)
    status = node["status"]["nodeInfo"]
    args = lab.command("docker", "exec", worker, "cat", "/var/lib/kubelet/kubeadm-flags.env").stdout
    observed = {
        "version_is_fixture": status.get("kubeletVersion") == "v1.37.0",
        "feature_explicitly_disabled": "--feature-gates=KubeletInUserNamespace=false" in args,
        "node_status_field_absent": FIELD not in status,
    }
    lab.check("red", "A v1.37 kubelet with reporting disabled omits the Node field",
              all(observed.values()), observed)


def rootless_report(lab):
    temp_root = "/private/tmp"
    with TemporaryDirectory(dir=temp_root, prefix="saf-rless-") as local:
        home = Path(local)
        lima = ("env", f"LIMA_HOME={home}", "limactl")
        try:
            lab.command(*lima, "start", "--plain", "--mount-none", f"--name={VM}", "--tty=false",
                        str(CASE / "test-vm.yaml"), timeout=300)
            guest = (*lima, "shell", VM, "bash")
            lab.command(*guest, "-s", payload=(CASE / "install-guest.sh").read_text(), timeout=360)
            output = lab.command(*guest, "-c", GUEST_LAUNCH,
                                 payload=(CASE / "rootless-guest.sh").read_text(), timeout=780).stdout
        finally:
            if (home / VM).is_dir():
                lab.command(*lima, "stop", "--force", VM, timeout=45)
                lab.command(*lima, "delete", "--force", VM, timeout=45)
                if (home / VM).exists():
                    lab.block("The owned Linux guest was not removed")
    keys = {
        "rootless", "reported_running_in_user_namespace", "kubelet_version", "container_runtime",
        "node_namespace_differs_from_guest_initial", "node_uid_map", "node_gid_map",
        "same_namespace_kubelet", "same_namespace_containerd", "same_namespace_kube-proxy",
        "same_namespace_kindnetd", "unlabelled_node_workload_pending", "verified_label_workload_succeeded",
        "issuer_is_independent_and_node_scoped", "node_restriction_denied_own_label",
        "stale_evidence_revoked_new_placement", "absent_evidence_revoked_new_placement",
        "previous_workload_remained_running", "fresh_evidence_restored_pending_placement",
        "owned_node_deleted",
    }
    return {
        name: value.strip()
        for name, _, value in (line.partition("=") for line in output.splitlines())
        if name in keys
    }


def delegated_map(layout):
    rows = [tuple(row.split(":")) for row in layout.split()]
    return (
        len(rows) >= 2 and all(len(row) == 3 and all(field.isdecimal() for field in row) for row in rows)
        and rows[0][0] == "0" and int(rows[0][1]) > 0 and rows[0][2] == "1"
        and any(int(size) >= 65536 and int(first) > 0 and int(host_first) > 0
                for first, host_first, size in rows[1:])
    )


def run(lab):
    if platform.system() != "Darwin" or platform.machine() != "arm64" or not shutil.which("limactl"):
        lab.block("The reproducible rootless leg requires Lima VZ on macOS ARM64")
    rootful_report(lab)
    absent_status_report(lab)
    observed = rootless_report(lab)
    uid_map, gid_map = (delegated_map(observed.get(f"node_{kind}_map", "")) for kind in ("uid", "gid"))
    components = {item: observed.get(f"same_namespace_{item}") == "true"
                  for item in ("kubelet", "containerd", "kube-proxy", "kindnetd")}
    namespace = {
        "rootless_podman_with_cgroupv2_systemd": observed.get("rootless") == "true cgroups=v2 manager=systemd",
        "kubelet_version": observed.get("kubelet_version"),
        "container_runtime": observed.get("container_runtime"),
        "node_reports_rootless": observed.get("reported_running_in_user_namespace") == "true",
        "independent_guest_namespace": observed.get("node_namespace_differs_from_guest_initial") == "true",
        "uid_and_gid_are_delegated": uid_map and gid_map,
        "components_share_namespace": components,
    }
    lab.check("green", "The Node signal agrees with live namespace membership on rootless Linux",
              namespace["rootless_podman_with_cgroupv2_systemd"] and namespace["kubelet_version"] == "v1.37.0"
              and namespace["node_reports_rootless"] and namespace["independent_guest_namespace"]
              and namespace["uid_and_gid_are_delegated"] and all(components.values()), namespace)
    identity = {
        name: observed.get(name) == "true" for name in (
            "issuer_is_independent_and_node_scoped", "node_restriction_denied_own_label",
        )
    }
    lab.check("green", "The scoped issuer can assign eligibility and the fixture node identity cannot",
              all(identity.values()), identity)
    eligibility = {
        name: observed.get(name) == "true" for name in (
            "unlabelled_node_workload_pending", "verified_label_workload_succeeded",
            "stale_evidence_revoked_new_placement", "previous_workload_remained_running",
            "fresh_evidence_restored_pending_placement", "absent_evidence_revoked_new_placement",
        )
    }
    lab.check("positive", "Scheduler eligibility follows corroborated freshness and existing placement persists",
              all(eligibility.values()), eligibility)
    lab.check("positive", "The independently owned rootless cluster and Linux guest were removed",
              observed.get("owned_node_deleted") == "true",
              {"rootless_node_deleted": observed.get("owned_node_deleted") == "true", "guest_removed": True})
