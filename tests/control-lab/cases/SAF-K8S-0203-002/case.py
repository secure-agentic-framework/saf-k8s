"""Verify an owned guest's applied sysctl profile and independent Pod IPC values."""

import hashlib
import json
from pathlib import Path
import platform
import shutil
from tempfile import TemporaryDirectory


CASE = Path(__file__).resolve().parent
SCOPE = (
    "A mount-free Debian ARM64 guest demonstrates node-style sysctl provisioning and "
    "effective values for a small profile. Two actual Kubernetes v1.36.1 Kind Pods "
    "independently demonstrate an IPC-namespaced sysctl. The guest and Kind are "
    "distinct environments. Production node pools, exemptions, and network response "
    "under load remain separate."
)
IMAGE = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
PROFILE = {
    "fs.suid_dumpable": "0",
    "kernel.dmesg_restrict": "1",
    "kernel.kptr_restrict": "2",
    "kernel.randomize_va_space": "2",
    "net.ipv4.tcp_syncookies": "1",
}
VM = "sysctl-fixture"
DROP_IN = "/etc/sysctl.d/90-saf-control-fixture.conf"


def guest_values(lab, guest):
    keys = list(PROFILE)
    files = ["/proc/sys/" + key.replace(".", "/") for key in keys]
    values = lab.command(*guest, "-c", "cat " + " ".join(files)).stdout.splitlines()
    if len(values) != len(keys) or any(not value.isdecimal() for value in values):
        lab.block("The owned guest did not expose all approved numeric sysctl settings")
    return dict(zip(keys, values))


def guest_checks(lab):
    with TemporaryDirectory(dir="/private/tmp", prefix="saf-sysctl-") as temp:
        home = Path(temp)
        lima = ("env", f"LIMA_HOME={home}", "limactl")
        try:
            lab.command(*lima, "start", "--plain", "--mount-none", f"--name={VM}", "--tty=false",
                        str(CASE / "test-vm.yaml"), timeout=300)
            guest = (*lima, "shell", VM, "bash")
            lab.command(
                *guest, "-c",
                f'test "$(hostname)" = lima-{VM} && test "$(uname -s)" = Linux '
                '&& test "$(uname -m)" = aarch64 '
                '&& ! findmnt -rn -t virtiofs,9p | grep -q . '
                f'&& test ! -e {DROP_IN}',
            )
            before = guest_values(lab, guest)
            stale = dict(PROFILE, **{"kernel.kptr_restrict": "1"})
            desired = "".join(f"{key} = {value}\n" for key, value in sorted(PROFILE.items()))
            stale_plan = "".join(f"{key} = {value}\n" for key, value in sorted(stale.items()))
            lab.check("red", "The fixture identifies missing provisioning and distinguishes the stale profile",
                      desired != stale_plan,
                      {"owned_guest_drop_in_absent": True, "observed_effective_values": before,
                       "stale_profile_differs": desired != stale_plan})
            lab.command(*guest, "-c", f"sudo -n tee {DROP_IN} >/dev/null", payload=desired)
            stored = lab.command(*guest, "-c", f"cat {DROP_IN}").stdout
            lab.command(
                *guest, "-c",
                f"if test -x /usr/sbin/sysctl; then sudo -n /usr/sbin/sysctl -p {DROP_IN} >/dev/null; "
                f"else sudo -n /usr/lib/systemd/systemd-sysctl {DROP_IN}; fi",
            )
            after = guest_values(lab, guest)
            lab.check("green", "The owned guest stores the approved drop-in and reports the exact effective values",
                      stored == desired and after == PROFILE,
                      {"profile_sha256": hashlib.sha256(stored.encode()).hexdigest(),
                       "effective_values": after,
                       "values_changed_from_baseline": sorted(key for key in PROFILE if before[key] != after[key])})
        finally:
            if (home / VM).is_dir():
                lab.command(*lima, "stop", "--force", VM, timeout=45)
                lab.command(*lima, "delete", "--force", VM, timeout=45)
                if (home / VM).exists():
                    lab.block("The owned sysctl guest was not removed")
    lab.check("positive", "The independent guest was removed", True, {"guest_removed": True})


def pod_values(lab):
    name = "kernel.shm_rmid_forced"
    observations = {}
    for value in ("0", "1"):
        pod = f"sysctl-ipc-{value}"
        lab.create({
            "apiVersion": "v1", "kind": "Pod", "metadata": {"name": pod},
            "spec": {
                "restartPolicy": "Never", "automountServiceAccountToken": False,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                    "seccompProfile": {"type": "RuntimeDefault"},
                                    "sysctls": [{"name": name, "value": value}]},
                "containers": [{
                    "name": "probe", "image": IMAGE,
                    "command": ["sh", "-c", "cat /proc/sys/kernel/shm_rmid_forced"],
                    "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
                }],
            },
        })
        lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{pod}",
                    "--timeout=90s", timeout=100)
        observations[value] = lab.kubectl("logs", f"pod/{pod}").stdout.strip()
    lab.check("positive", "Two Pods on the same Kind node observe independent safe IPC sysctl values",
              observations == {"0": "0", "1": "1"},
              {"sysctl": name, "value_by_requested": observations})


def run(lab):
    if platform.system() != "Darwin" or platform.machine() != "arm64" or not shutil.which("limactl"):
        lab.block("The mount-free Debian guest requires Lima VZ on macOS ARM64")
    guest_checks(lab)
    pod_values(lab)
