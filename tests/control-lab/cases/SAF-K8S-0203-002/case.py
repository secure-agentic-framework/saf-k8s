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
    "effective values for a small profile before and after reboot. Read-only forwarding "
    "and reverse-path-filter observations record guest scope without prescribing values. "
    "Two actual Kubernetes v1.36.1 Kind Pods independently demonstrate an IPC-namespaced "
    "sysctl. The guest and Kind are distinct environments. Production role profiles, "
    "CNI/RDMA compatibility, and managed-provider attestations remain adopter evidence."
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


def boot_id(lab, guest):
    value = lab.command(*guest, "-c", "cat /proc/sys/kernel/random/boot_id").stdout.strip()
    if len(value) != 36 or value.count("-") != 4:
        lab.block("The owned guest did not expose a valid kernel boot ID")
    return value


def apply_guest_profile(lab, guest):
    lab.command(
        *guest, "-c",
        f"if test -x /usr/sbin/sysctl; then sudo -n /usr/sbin/sysctl -p {DROP_IN} >/dev/null; "
        f"else sudo -n /usr/lib/systemd/systemd-sysctl {DROP_IN}; fi",
    )


def network_scope(lab, guest):
    script = r'''set -eu
printf 'net.ipv4.ip_forward=%s\n' "$(cat /proc/sys/net/ipv4/ip_forward)"
printf 'net.ipv6.conf.all.forwarding=%s\n' "$(cat /proc/sys/net/ipv6/conf/all/forwarding)"
for file in /proc/sys/net/ipv4/conf/*/rp_filter; do
    [ -r "$file" ] || continue
    name=${file#/proc/sys/net/ipv4/conf/}
    name=${name%/rp_filter}
    printf 'net.ipv4.conf.%s.rp_filter=%s\n' "$name" "$(cat "$file")"
done'''
    lines = lab.command(*guest, "-c", script).stdout.splitlines()
    observations = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator or not value.isdecimal():
            lab.block("The guest network sysctl scope observation was incomplete")
        observations[key] = value
    required = {
        "net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding",
        "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter",
    }
    if not required.issubset(observations):
        lab.block("The guest did not expose the required forwarding/rp_filter scope")
    return observations


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
            first_boot = boot_id(lab, guest)
            stale = dict(PROFILE, **{"kernel.kptr_restrict": "1"})
            stale_config = "".join(f"{key} = {value}\n" for key, value in sorted(stale.items()))
            lab.command(*guest, "-c", f"sudo -n tee {DROP_IN} >/dev/null", payload=stale_config)
            stale_stored = lab.command(*guest, "-c", f"cat {DROP_IN}").stdout
            apply_guest_profile(lab, guest)
            stale_observed = guest_values(lab, guest)
            red = (
                stale_stored == stale_config
                and stale_observed == stale
                and stale_observed["kernel.kptr_restrict"] == "1"
                and stale_observed["kernel.kptr_restrict"] != PROFILE["kernel.kptr_restrict"]
            )
            lab.check("red", "The installed stale profile is detected from exact effective values",
                      red,
                      {"installed_profile_sha256": hashlib.sha256(stale_stored.encode()).hexdigest(),
                       "observed_effective_values": stale_observed,
                       "required_kernel.kptr_restrict": PROFILE["kernel.kptr_restrict"]})
            desired = "".join(f"{key} = {value}\n" for key, value in sorted(PROFILE.items()))
            lab.command(*guest, "-c", f"sudo -n tee {DROP_IN} >/dev/null", payload=desired)
            stored = lab.command(*guest, "-c", f"cat {DROP_IN}").stdout
            apply_guest_profile(lab, guest)
            after = guest_values(lab, guest)
            lab.check("green", "The owned guest stores the approved drop-in and reports the exact effective values",
                      stored == desired and after == PROFILE,
                      {"profile_sha256": hashlib.sha256(stored.encode()).hexdigest(),
                       "effective_values": after,
                       "values_changed_from_baseline": sorted(key for key in PROFILE if before[key] != after[key])})
            observed_network = network_scope(lab, guest)
            lab.check("positive", "The fixture records read-only forwarding and reverse-path-filter scope",
                      bool(observed_network), {"guest_network_scope_observed": bool(observed_network)})

            lab.command(*guest, "-c", "sudo -n tee /proc/sys/kernel/kptr_restrict >/dev/null",
                        payload="1\n")
            drifted = guest_values(lab, guest)
            drifted_file = lab.command(*guest, "-c", f"cat {DROP_IN}").stdout
            lab.check("red", "Runtime-only drift differs from the unchanged approved persistent profile",
                      drifted == stale and drifted_file == desired,
                      {"runtime_kptr_restrict": drifted["kernel.kptr_restrict"],
                       "approved_persistent_value": PROFILE["kernel.kptr_restrict"]})
            lab.command(*lima, "stop", VM, timeout=70)
            lab.command(*lima, "start", "--tty=false", VM, timeout=300)
            rebooted = boot_id(lab, guest)
            reboot_stored = lab.command(*guest, "-c", f"cat {DROP_IN}").stdout
            unit = lab.command(
                *guest, "-c",
                "test \"$(systemctl show -p Result --value systemd-sysctl.service)\" = success "
                "&& test \"$(systemctl show -p ExecMainStatus --value systemd-sysctl.service)\" = 0 "
                "&& systemctl is-active --quiet systemd-sysctl.service "
                "&& printf 'result=success\\nexec_main_status=0\\nactive=yes\\n'",
            ).stdout
            after_reboot = guest_values(lab, guest)
            lab.check("green", "The same guest boots with the approved profile applied by its normal sysctl unit",
                      rebooted != first_boot and reboot_stored == desired and unit.splitlines() == [
                          "result=success", "exec_main_status=0", "active=yes"] and after_reboot == PROFILE,
                      {"guest_boot_id_changed": rebooted != first_boot,
                       "stored_profile_sha256": hashlib.sha256(reboot_stored.encode()).hexdigest(),
                       "systemd_sysctl_unit": unit.splitlines(),
                       "effective_values_after_reboot_without_reapplication": after_reboot})
            (lab.evidence / "sysctl-guest-observations.json").write_text(json.dumps({
                "boot_id_before": first_boot,
                "boot_id_after": rebooted,
                "initial_values": before,
                "stale_values": stale_observed,
                "runtime_drift": drifted,
                "values_after_boot": after_reboot,
                "network_scope_observations": observed_network,
                "systemd_sysctl_unit": unit.splitlines(),
            }, indent=2) + "\n")
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
